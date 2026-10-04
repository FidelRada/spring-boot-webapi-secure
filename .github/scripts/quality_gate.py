#!/usr/bin/env python3
"""Quality Gate del pipeline de seguridad (Laboratorio 3).

Lee el CONTENIDO de los reportes de seguridad (no solo el estado de los jobs) y decide
si el run se aprueba o se bloquea. Es fail-closed: si un reporte requerido falta, está
vacío o no se puede parsear, el gate falla.

Política de bloqueo:
  - Semgrep (SARIF):          nivel efectivo == error (result.level o, si falta,
                               defaultConfiguration.level de la regla).
  - CodeQL (SARIF):           security-severity >= 7.0 (reglas en tool.driver.rules
                               o en tool.extensions[].rules).
  - SpotBugs + FindSecBugs:   categoría SECURITY y prioridad <= 2.
  - Dependency-Check (JSON):  CVSS >= 7.0 o severidad HIGH/CRITICAL; las vulnerabilidades
                               suprimidas se listan, pero no bloquean.
  - Trivy (JSON, SBOM/imagen): Severity HIGH o CRITICAL.

Códigos de salida:
  0  aprobado
  1  hallazgos bloqueantes, o jobs en failure/cancelled, o job requerido skipped
  2  reporte requerido faltante, vacío o ilegible (fail-closed)

Solo usa la biblioteca estándar de Python 3.
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

UMBRAL_CVSS = 7.0
UMBRAL_SECURITY_SEVERITY = 7.0
PRIORIDAD_MAXIMA_SPOTBUGS = 2
SEVERIDADES_BLOQUEANTES = {"HIGH", "CRITICAL"}

EXIT_OK = 0
EXIT_BLOQUEADO = 1
EXIT_FAIL_CLOSED = 2


class ReportError(Exception):
    """El reporte existe pero está vacío o no se puede interpretar."""


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    location: str
    blocking: bool
    suppressed: bool = False


@dataclass
class GateResult:
    findings: list = field(default_factory=list)
    # Elementos (herramienta, archivo o patrón, motivo).
    missing: list = field(default_factory=list)
    # Elementos (job, resultado).
    failed_jobs: list = field(default_factory=list)
    evaluated_files: list = field(default_factory=list)

    @property
    def blocking(self) -> list:
        return [f for f in self.findings if f.blocking]

    def exit_code(self) -> int:
        if self.failed_jobs:
            return EXIT_BLOQUEADO
        if self.missing:
            return EXIT_FAIL_CLOSED
        if self.blocking:
            return EXIT_BLOQUEADO
        return EXIT_OK

    def verdict(self) -> str:
        code = self.exit_code()
        if code == EXIT_OK:
            return "APROBADO"
        if code == EXIT_FAIL_CLOSED:
            return "BLOQUEADO (fail-closed: reporte faltante o ilegible)"
        return "BLOQUEADO"


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _leer_texto(path: Path) -> str:
    try:
        texto = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReportError(f"no se pudo leer: {exc}") from exc
    if not texto.strip():
        raise ReportError("archivo vacío")
    return texto


def _leer_json(path: Path):
    try:
        return json.loads(_leer_texto(path))
    except json.JSONDecodeError as exc:
        raise ReportError(f"JSON inválido: {exc}") from exc


class ReportParser:
    """Clase base: cada parser sabe qué archivos le corresponden y cómo leerlos."""

    tool: str = ""
    # Cada patrón (glob recursivo) debe coincidir con al menos un archivo si la
    # herramienta es requerida.
    patterns: list = []

    def parse(self, path: Path) -> list:  # pragma: no cover - abstracto
        raise NotImplementedError


class SarifParser(ReportParser):
    """Base para reportes SARIF 2.1.0."""

    def parse(self, path: Path) -> list:
        data = _leer_json(path)
        if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
            raise ReportError("no es un SARIF válido (falta 'runs')")
        hallazgos = []
        for run in data["runs"]:
            reglas = self._indice_reglas(run)
            for result in run.get("results") or []:
                rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or "?"
                regla = reglas.get(rule_id, {})
                hallazgos.append(
                    Finding(
                        tool=self.tool,
                        rule=rule_id,
                        severity=self.severity(result, regla),
                        location=self._ubicacion(result),
                        blocking=self.is_blocking(result, regla),
                    )
                )
        return hallazgos

    @staticmethod
    def _indice_reglas(run: dict) -> dict:
        tool = run.get("tool") or {}
        componentes = [tool.get("driver") or {}] + list(tool.get("extensions") or [])
        indice = {}
        for componente in componentes:
            for regla in componente.get("rules") or []:
                if isinstance(regla, dict) and regla.get("id"):
                    indice.setdefault(regla["id"], regla)
        return indice

    @staticmethod
    def _ubicacion(result: dict) -> str:
        for loc in result.get("locations") or []:
            fisica = loc.get("physicalLocation") or {}
            uri = (fisica.get("artifactLocation") or {}).get("uri", "?")
            linea = (fisica.get("region") or {}).get("startLine")
            return f"{uri}:{linea}" if linea else uri
        return "?"

    @staticmethod
    def nivel_efectivo(result: dict, regla: dict) -> str:
        nivel = result.get("level")
        if not nivel:
            nivel = (regla.get("defaultConfiguration") or {}).get("level")
        return (nivel or "warning").lower()

    def severity(self, result: dict, regla: dict) -> str:
        return self.nivel_efectivo(result, regla)

    def is_blocking(self, result: dict, regla: dict) -> bool:
        return self.nivel_efectivo(result, regla) == "error"


class SemgrepParser(SarifParser):
    tool = "semgrep"
    patterns = ["semgrep.sarif"]


class CodeQLParser(SarifParser):
    tool = "codeql"
    patterns = ["codeql*.sarif"]

    @staticmethod
    def security_severity(regla: dict):
        valor = (regla.get("properties") or {}).get("security-severity")
        try:
            return float(valor)
        except (TypeError, ValueError):
            return None

    def severity(self, result: dict, regla: dict) -> str:
        sev = self.security_severity(regla)
        nivel = self.nivel_efectivo(result, regla)
        return f"{sev:.1f} ({nivel})" if sev is not None else nivel

    def is_blocking(self, result: dict, regla: dict) -> bool:
        sev = self.security_severity(regla)
        return sev is not None and sev >= UMBRAL_SECURITY_SEVERITY


class SpotBugsParser(ReportParser):
    tool = "spotbugs"
    patterns = ["spotbugsXml.xml"]

    def parse(self, path: Path) -> list:
        try:
            raiz = ET.fromstring(_leer_texto(path))
        except ET.ParseError as exc:
            raise ReportError(f"XML inválido: {exc}") from exc
        if raiz.tag != "BugCollection":
            raise ReportError("no es un reporte de SpotBugs (falta BugCollection)")
        hallazgos = []
        for bug in raiz.iter("BugInstance"):
            categoria = bug.get("category", "")
            try:
                prioridad = int(bug.get("priority", "3"))
            except ValueError:
                prioridad = 3
            clase = bug.find("Class")
            ubicacion = clase.get("classname", "?") if clase is not None else "?"
            linea = bug.find("SourceLine")
            if linea is not None and linea.get("start"):
                ubicacion = f"{linea.get('sourcepath', ubicacion)}:{linea.get('start')}"
            hallazgos.append(
                Finding(
                    tool=self.tool,
                    rule=f"{categoria}/{bug.get('type', '?')}",
                    severity=f"prioridad {prioridad}",
                    location=ubicacion,
                    blocking=categoria == "SECURITY" and prioridad <= PRIORIDAD_MAXIMA_SPOTBUGS,
                )
            )
        return hallazgos


class DependencyCheckParser(ReportParser):
    tool = "dependency-check"
    patterns = ["dependency-check-report.json"]

    @staticmethod
    def _puntuacion(vuln: dict):
        puntuaciones = []
        for clave in ("cvssv4", "cvssv3", "cvssv2"):
            bloque = vuln.get(clave)
            if not isinstance(bloque, dict):
                continue
            for candidato in (
                bloque.get("baseScore"),
                bloque.get("score"),
                (bloque.get("cvssData") or {}).get("baseScore"),
            ):
                try:
                    puntuaciones.append(float(candidato))
                except (TypeError, ValueError):
                    continue
        return max(puntuaciones) if puntuaciones else None

    def _finding(self, dep: dict, vuln: dict, suprimida: bool) -> Finding:
        puntuacion = self._puntuacion(vuln)
        severidad = str(vuln.get("severity") or "").upper()
        bloquea = (puntuacion is not None and puntuacion >= UMBRAL_CVSS) or (
            severidad in SEVERIDADES_BLOQUEANTES
        )
        texto = severidad or "?"
        if puntuacion is not None:
            texto = f"{texto} (CVSS {puntuacion:.1f})"
        return Finding(
            tool=self.tool,
            rule=vuln.get("name", "?"),
            severity=texto,
            location=dep.get("fileName", "?"),
            blocking=bloquea and not suprimida,
            suppressed=suprimida,
        )

    def parse(self, path: Path) -> list:
        data = _leer_json(path)
        if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
            raise ReportError("no es un reporte de Dependency-Check (falta 'dependencies')")
        hallazgos = []
        for dep in data["dependencies"]:
            for vuln in dep.get("vulnerabilities") or []:
                hallazgos.append(self._finding(dep, vuln, suprimida=False))
            for vuln in dep.get("suppressedVulnerabilities") or []:
                hallazgos.append(self._finding(dep, vuln, suprimida=True))
        return hallazgos


class TrivyParser(ReportParser):
    tool = "trivy"
    patterns = ["sca-report.json"]

    def parse(self, path: Path) -> list:
        data = _leer_json(path)
        if not isinstance(data, dict) or "SchemaVersion" not in data:
            raise ReportError("no es un reporte JSON de Trivy (falta 'SchemaVersion')")
        hallazgos = []
        for resultado in data.get("Results") or []:
            objetivo = resultado.get("Target", "?")
            for vuln in resultado.get("Vulnerabilities") or []:
                severidad = str(vuln.get("Severity", "UNKNOWN")).upper()
                paquete = vuln.get("PkgName", "?")
                version = vuln.get("InstalledVersion", "")
                hallazgos.append(
                    Finding(
                        tool=self.tool,
                        rule=vuln.get("VulnerabilityID", "?"),
                        severity=severidad,
                        location=f"{paquete}@{version} ({objetivo})",
                        blocking=severidad in SEVERIDADES_BLOQUEANTES,
                    )
                )
        return hallazgos


class TrivyImagenParser(TrivyParser):
    """Trivy sobre la imagen: pasada de SO (--ignore-unfixed) y de librerías (sin filtro)."""

    tool = "trivy-imagen"
    patterns = ["trivy-imagen-os.json", "trivy-imagen-app.json"]


PARSERS = {
    p.tool: p
    for p in (
        SemgrepParser(),
        CodeQLParser(),
        SpotBugsParser(),
        DependencyCheckParser(),
        TrivyParser(),
        TrivyImagenParser(),
    )
}
HERRAMIENTAS_POR_DEFECTO = ["semgrep", "codeql", "spotbugs", "trivy", "dependency-check"]

# Job del workflow reutilizable que produce cada reporte (para detectar requeridos skipped).
JOB_POR_HERRAMIENTA = {
    "semgrep": "sast-semgrep",
    "codeql": "sast-codeql",
    "spotbugs": "sast-spotbugs",
    "trivy": "sca-sbom-trivy",
    "dependency-check": "sca-dependency-check",
}
JOBS_SIEMPRE_REQUERIDOS = {"build-test"}


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


class QualityGate:
    def __init__(self, reports_dir, required=None, needs=None, only=None):
        self.reports_dir = Path(reports_dir)
        self.only = list(only) if only else None
        evaluables = self.only or HERRAMIENTAS_POR_DEFECTO
        self.required = set(required) if required is not None else set(evaluables)
        desconocidas = (self.required | set(evaluables)) - set(PARSERS)
        if desconocidas:
            raise ValueError(f"herramientas desconocidas: {', '.join(sorted(desconocidas))}")
        # Los requeridos siempre se evalúan; los demás, solo si su reporte existe.
        self.tools = list(dict.fromkeys(list(evaluables) + sorted(self.required)))
        self.needs = needs or {}

    def _buscar(self, patron: str) -> list:
        if not self.reports_dir.is_dir():
            return []
        return sorted(p for p in self.reports_dir.rglob(patron) if p.is_file())

    def _evaluar_jobs(self, resultado: GateResult) -> None:
        jobs_requeridos = set(JOBS_SIEMPRE_REQUERIDOS)
        jobs_requeridos |= {JOB_POR_HERRAMIENTA[t] for t in self.required if t in JOB_POR_HERRAMIENTA}
        for job, info in sorted(self.needs.items()):
            estado = (info or {}).get("result", "") if isinstance(info, dict) else str(info)
            if estado in ("failure", "cancelled"):
                resultado.failed_jobs.append((job, estado))
            elif estado == "skipped" and job in jobs_requeridos:
                resultado.failed_jobs.append((job, "skipped (requerido)"))

    def evaluate(self) -> GateResult:
        resultado = GateResult()
        self._evaluar_jobs(resultado)
        for tool in self.tools:
            parser = PARSERS[tool]
            requerido = tool in self.required
            for patron in parser.patterns:
                archivos = self._buscar(patron)
                if not archivos:
                    if requerido:
                        resultado.missing.append((tool, patron, "reporte faltante"))
                    continue
                for archivo in archivos:
                    try:
                        resultado.findings.extend(parser.parse(archivo))
                        resultado.evaluated_files.append((tool, str(archivo)))
                    except ReportError as exc:
                        # Un reporte presente pero ilegible siempre es fail-closed.
                        resultado.missing.append((tool, str(archivo), f"reporte ilegible: {exc}"))
        return resultado

    @staticmethod
    def write_summary(resultado: GateResult, max_filas: int = 200) -> str:
        def celda(texto) -> str:
            # Sin "|" ni saltos de línea (romperían la tabla) ni "`" (cerraría el código).
            return str(texto).replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("`", "'")

        lineas = ["## Quality Gate de seguridad", ""]
        icono = "✅" if resultado.exit_code() == EXIT_OK else "❌"
        lineas.append(f"**Veredicto: {icono} {resultado.verdict()}** (código de salida {resultado.exit_code()})")
        lineas.append("")
        bloqueantes = resultado.blocking
        suprimidos = [f for f in resultado.findings if f.suppressed]
        informativos = [f for f in resultado.findings if not f.blocking and not f.suppressed]
        lineas.append(
            f"- Hallazgos bloqueantes: **{len(bloqueantes)}** · no bloqueantes: {len(informativos)}"
            f" · suprimidos: {len(suprimidos)}"
        )
        lineas.append(
            f"- Política: Semgrep `error`; CodeQL security-severity ≥ {UMBRAL_SECURITY_SEVERITY}; "
            f"SpotBugs SECURITY prioridad ≤ {PRIORIDAD_MAXIMA_SPOTBUGS}; "
            f"Dependency-Check CVSS ≥ {UMBRAL_CVSS} o HIGH/CRITICAL; Trivy HIGH/CRITICAL"
        )
        lineas.append("")

        conteo = {}
        for f in resultado.findings:
            c = conteo.setdefault(f.tool, [0, 0, 0])
            c[0 if f.blocking else (2 if f.suppressed else 1)] += 1
        if resultado.evaluated_files or conteo:
            lineas += ["### Reportes evaluados", "", "| Herramienta | Bloqueantes | No bloqueantes | Suprimidos |", "|---|---|---|---|"]
            for tool in sorted({t for t, _ in resultado.evaluated_files} | set(conteo)):
                b, n, s = conteo.get(tool, [0, 0, 0])
                lineas.append(f"| {tool} | {b} | {n} | {s} |")
            lineas.append("")

        if resultado.failed_jobs:
            lineas += ["### Jobs fallidos u omitidos", "", "| Job | Resultado |", "|---|---|"]
            lineas += [f"| {celda(j)} | {celda(r)} |" for j, r in resultado.failed_jobs]
            lineas.append("")
        if resultado.missing:
            lineas += ["### Reportes faltantes o ilegibles (fail-closed)", "", "| Herramienta | Archivo | Motivo |", "|---|---|---|"]
            lineas += [f"| {celda(t)} | `{celda(a)}` | {celda(m)} |" for t, a, m in resultado.missing]
            lineas.append("")

        def tabla(titulo, filas, bloquea):
            if not filas:
                return
            lineas.extend([f"### {titulo}", "", "| Herramienta | Regla / CVE | Severidad | Ubicación | Bloquea |", "|---|---|---|---|---|"])
            for f in filas[:max_filas]:
                lineas.append(
                    f"| {celda(f.tool)} | `{celda(f.rule)}` | {celda(f.severity)} | `{celda(f.location)}` | {bloquea} |"
                )
            if len(filas) > max_filas:
                lineas.append(f"| … | {len(filas) - max_filas} filas más | | | |")
            lineas.append("")

        tabla("Hallazgos bloqueantes", bloqueantes, "sí")
        tabla("Hallazgos no bloqueantes", informativos, "no")
        tabla("Vulnerabilidades suprimidas (Dependency-Check)", suprimidos, "no (suprimida)")
        return "\n".join(lineas) + "\n"


def escapar_comando(texto) -> str:
    """Escapa datos de un comando de workflow (::error::) según la especificación de Actions.

    Los nombres de archivo, reglas y CVE vienen de los reportes (y en un PR, del código del
    autor): sin escapar, un salto de línea permitiría inyectar otro comando "::...::".
    """
    return str(texto).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _cargar_needs(valor):
    if not valor:
        return {}
    texto = valor
    if not valor.lstrip().startswith("{"):
        texto = Path(valor).read_text(encoding="utf-8")
    datos = json.loads(texto)
    if not isinstance(datos, dict):
        raise ValueError("--needs-json debe ser un objeto JSON")
    return datos


def _lista(valor):
    if valor is None:
        return None
    return [x.strip() for x in valor.split(",") if x.strip()]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Quality Gate que lee los reportes de seguridad (fail-closed).")
    parser.add_argument("--reports-dir", required=True, help="carpeta con los reportes (se busca de forma recursiva)")
    parser.add_argument(
        "--required",
        help="herramientas cuyo reporte es obligatorio, separadas por comas "
        f"(por defecto: {','.join(HERRAMIENTAS_POR_DEFECTO)}, o las de --only)",
    )
    parser.add_argument("--only", help="evaluar solo estas herramientas (p. ej. trivy-imagen)")
    parser.add_argument("--needs-json", help="JSON de toJSON(needs) del workflow, o ruta a un archivo con él")
    parser.add_argument(
        "--summary",
        action="append",
        default=[],
        help="archivo Markdown donde AÑADIR el resumen (p. ej. $GITHUB_STEP_SUMMARY); se puede repetir",
    )
    args = parser.parse_args(argv)

    try:
        gate = QualityGate(
            args.reports_dir,
            required=_lista(args.required),
            needs=_cargar_needs(args.needs_json),
            only=_lista(args.only),
        )
    except (ValueError, OSError) as exc:
        print(f"::error::Configuración inválida del gate: {exc}")
        return EXIT_FAIL_CLOSED

    resultado = gate.evaluate()
    resumen = QualityGate.write_summary(resultado)
    for destino in args.summary:
        with open(destino, "a", encoding="utf-8") as fh:
            fh.write(resumen)

    for job, estado in resultado.failed_jobs:
        print(f"::error::Job '{escapar_comando(job)}' terminó en {escapar_comando(estado)}")
    for tool, archivo, motivo in resultado.missing:
        print(f"::error::[{tool}] {escapar_comando(motivo)}: {escapar_comando(archivo)}")
    for f in resultado.blocking:
        print(
            f"::error::[{f.tool}] {escapar_comando(f.rule)} ({escapar_comando(f.severity)}) "
            f"en {escapar_comando(f.location)}"
        )
    print(
        f"Quality Gate: {resultado.verdict()} — {len(resultado.blocking)} bloqueantes, "
        f"{len(resultado.findings) - len(resultado.blocking)} no bloqueantes/suprimidos, "
        f"{len(resultado.missing)} reportes faltantes/ilegibles, {len(resultado.failed_jobs)} jobs fallidos"
    )
    return resultado.exit_code()


if __name__ == "__main__":
    sys.exit(main())
