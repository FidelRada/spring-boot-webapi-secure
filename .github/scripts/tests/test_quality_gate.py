"""Pruebas unitarias del Quality Gate: política de bloqueo, fail-closed y resumen.

Ejecutar desde la raíz del repositorio:
    python3 -m unittest discover -s .github/scripts/tests -v
"""

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

DIR_TESTS = Path(__file__).resolve().parent
FIXTURES = DIR_TESTS / "fixtures"
sys.path.insert(0, str(DIR_TESTS.parent))

import quality_gate as qg  # noqa: E402

# Nombre que tiene cada reporte dentro de los artifacts del pipeline.
NOMBRES = {
    "semgrep": "reporte-semgrep/semgrep.sarif",
    "codeql": "reporte-codeql/codeql.sarif",
    "spotbugs": "reporte-spotbugs/spotbugsXml.xml",
    "dependency-check": "reporte-dependency-check/dependency-check-report.json",
    "trivy": "reporte-trivy-sbom/sca-report.json",
    "trivy-imagen-os": "reporte-trivy-imagen/trivy-imagen-os.json",
    "trivy-imagen-app": "reporte-trivy-imagen/trivy-imagen-app.json",
}

LIMPIOS = {
    "semgrep": "semgrep_solo_warning.sarif",
    "codeql": "codeql_limpio.sarif",
    "spotbugs": "spotbugs_limpio.xml",
    "dependency-check": "dc_suprimido.json",
    "trivy": "trivy_sbom_limpio.json",
}

NEEDS_OK = {
    "build-test": {"result": "success", "outputs": {}},
    "sast-semgrep": {"result": "success", "outputs": {}},
    "sast-codeql": {"result": "success", "outputs": {}},
    "sast-spotbugs": {"result": "success", "outputs": {}},
    "sca-sbom-trivy": {"result": "success", "outputs": {}},
    "sca-dependency-check": {"result": "success", "outputs": {}},
}


class BaseGate(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="gate-"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def colocar(self, **reportes):
        """colocar(semgrep='semgrep_rojo.sarif', ...) copia fixtures con el nombre del pipeline."""
        for clave, fixture in reportes.items():
            clave = clave.replace("_", "-")
            destino = self.dir / NOMBRES[clave]
            destino.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(FIXTURES / fixture, destino)

    def colocar_limpios(self, **reemplazos):
        base = dict(LIMPIOS)
        base.update({k.replace("_", "-"): v for k, v in reemplazos.items()})
        for clave, fixture in base.items():
            if fixture is not None:
                self.colocar(**{clave: fixture})

    def ejecutar(self, *args):
        salida = io.StringIO()
        resumen = self.dir / "resumen.md"
        with contextlib.redirect_stdout(salida):
            codigo = qg.main(["--reports-dir", str(self.dir), "--summary", str(resumen), *args])
        texto = resumen.read_text(encoding="utf-8") if resumen.exists() else ""
        return codigo, texto, salida.getvalue()


class TestParsers(BaseGate):
    def test_semgrep_nivel_desde_default_configuration(self):
        """Semgrep OSS no escribe result.level; se usa el nivel por defecto de la regla."""
        hallazgos = qg.SemgrepParser().parse(FIXTURES / "semgrep_rojo.sarif")
        por_regla = {f.rule: f for f in hallazgos}
        self.assertTrue(por_regla["lab-java-sql-concatenation"].blocking)
        self.assertEqual(por_regla["lab-java-sql-concatenation"].severity, "error")
        self.assertFalse(por_regla["lab-csrf-disabled"].blocking)
        self.assertIn("ProductController.java", por_regla["lab-java-sql-concatenation"].location)

    def test_semgrep_result_level_tiene_prioridad(self):
        datos = json.loads((FIXTURES / "semgrep_solo_warning.sarif").read_text(encoding="utf-8"))
        datos["runs"][0]["results"][0]["level"] = "error"
        ruta = self.dir / "semgrep.sarif"
        ruta.write_text(json.dumps(datos), encoding="utf-8")
        self.assertTrue(any(f.blocking for f in qg.SemgrepParser().parse(ruta)))

    def test_codeql_security_severity_en_extensions(self):
        hallazgos = qg.CodeQLParser().parse(FIXTURES / "codeql_rojo.sarif")
        por_regla = {f.rule: f for f in hallazgos}
        self.assertTrue(por_regla["java/sql-injection"].blocking)
        self.assertFalse(por_regla["java/log-injection"].blocking)
        self.assertIn("8.8", por_regla["java/sql-injection"].severity)

    def test_spotbugs_prioridades(self):
        hallazgos = qg.SpotBugsParser().parse(FIXTURES / "spotbugs_rojo.xml")
        por_tipo = {f.rule: f for f in hallazgos}
        self.assertTrue(por_tipo["SECURITY/SPRING_CSRF_PROTECTION_DISABLED"].blocking)  # prioridad 1
        self.assertTrue(por_tipo["SECURITY/SQL_INJECTION_SPRING_JDBC"].blocking)  # prioridad 2
        self.assertFalse(por_tipo["SECURITY/SPRING_ENDPOINT"].blocking)  # prioridad 3
        self.assertFalse(por_tipo["MALICIOUS_CODE/EI_EXPOSE_REP2"].blocking)  # no es SECURITY

    def test_dependency_check_cvss(self):
        hallazgos = qg.DependencyCheckParser().parse(FIXTURES / "dc_rojo.json")
        self.assertEqual([f.rule for f in hallazgos if f.blocking], ["CVE-2022-42889"])

    def test_trivy_high_critical(self):
        hallazgos = qg.TrivyParser().parse(FIXTURES / "trivy_sbom_rojo.json")
        self.assertEqual([(f.rule, f.severity) for f in hallazgos if f.blocking], [("CVE-2022-42889", "CRITICAL")])


class TestPoliticaDelGate(BaseGate):
    def test_cve_critico_en_trivy_bloquea(self):
        self.colocar_limpios(trivy="trivy_sbom_rojo.json")
        codigo, resumen, _ = self.ejecutar("--required", "semgrep,codeql,spotbugs,trivy,dependency-check")
        self.assertEqual(codigo, 1)
        self.assertIn("CVE-2022-42889", resumen)
        self.assertIn("BLOQUEADO", resumen)

    def test_cve_critico_en_dependency_check_bloquea(self):
        self.colocar_limpios(dependency_check="dc_rojo.json")
        codigo, resumen, _ = self.ejecutar()
        self.assertEqual(codigo, 1)
        self.assertIn("CVE-2022-42889", resumen)

    def test_semgrep_error_bloquea_con_herramienta_regla_ubicacion(self):
        self.colocar_limpios(semgrep="semgrep_rojo.sarif")
        codigo, resumen, salida = self.ejecutar()
        self.assertEqual(codigo, 1)
        self.assertIn("| semgrep | `lab-java-sql-concatenation`", resumen)
        self.assertIn("ProductController.java", salida)

    def test_codeql_severidad_alta_bloquea(self):
        self.colocar_limpios(codeql="codeql_rojo.sarif")
        codigo, resumen, _ = self.ejecutar()
        self.assertEqual(codigo, 1)
        self.assertIn("java/sql-injection", resumen)

    def test_solo_hallazgos_menores_no_bloquea(self):
        self.colocar_limpios()
        codigo, resumen, _ = self.ejecutar()
        self.assertEqual(codigo, 0)
        self.assertIn("Hallazgos no bloqueantes", resumen)
        self.assertIn("lab-csrf-disabled", resumen)  # warning listado como no bloqueante
        self.assertIn("java/log-injection", resumen)  # CodeQL 5.0 listado como no bloqueante

    def test_spotbugs_security_prioridad_2_bloquea(self):
        self.colocar_limpios(spotbugs="spotbugs_rojo.xml")
        codigo, resumen, _ = self.ejecutar()
        self.assertEqual(codigo, 1)
        self.assertIn("SQL_INJECTION_SPRING_JDBC", resumen)
        bloque_no_bloqueantes = resumen.split("### Hallazgos no bloqueantes", 1)[1]
        self.assertIn("SPRING_ENDPOINT", bloque_no_bloqueantes)

    def test_vulnerabilidad_suprimida_no_bloquea(self):
        self.colocar_limpios(dependency_check="dc_suprimido.json")
        codigo, resumen, _ = self.ejecutar()
        self.assertEqual(codigo, 0)
        self.assertIn("Vulnerabilidades suprimidas", resumen)
        self.assertIn("CVE-2022-42889", resumen)

    def test_reporte_faltante_fail_closed(self):
        self.colocar_limpios(trivy=None)
        codigo, resumen, _ = self.ejecutar()
        self.assertEqual(codigo, 2)
        self.assertIn("reporte faltante", resumen)

    def test_reporte_vacio_fail_closed(self):
        self.colocar_limpios()
        (self.dir / NOMBRES["trivy"]).write_text("", encoding="utf-8")
        codigo, resumen, _ = self.ejecutar()
        self.assertEqual(codigo, 2)
        self.assertIn("reporte ilegible", resumen)

    def test_reporte_corrupto_fail_closed(self):
        self.colocar_limpios(semgrep="corrupto.sarif")
        codigo, resumen, _ = self.ejecutar()
        self.assertEqual(codigo, 2)
        self.assertIn("reporte ilegible", resumen)

    def test_build_roto_bloquea(self):
        self.colocar_limpios()
        needs = dict(NEEDS_OK, **{"build-test": {"result": "failure", "outputs": {}}})
        codigo, resumen, salida = self.ejecutar("--needs-json", json.dumps(needs))
        self.assertEqual(codigo, 1)
        self.assertIn("build-test", resumen)
        self.assertIn("failure", salida)

    def test_job_requerido_omitido_falla(self):
        self.colocar_limpios(dependency_check=None)
        needs = dict(NEEDS_OK, **{"sca-dependency-check": {"result": "skipped", "outputs": {}}})
        codigo, _, _ = self.ejecutar(
            "--required", "semgrep,codeql,spotbugs,trivy,dependency-check", "--needs-json", json.dumps(needs)
        )
        self.assertNotEqual(codigo, 0)

    def test_push_feature_no_exige_dependency_check(self):
        self.colocar_limpios(dependency_check=None)
        needs = dict(NEEDS_OK, **{"sca-dependency-check": {"result": "skipped", "outputs": {}}})
        codigo, _, _ = self.ejecutar("--required", "semgrep,codeql,spotbugs,trivy", "--needs-json", json.dumps(needs))
        self.assertEqual(codigo, 0)

    def test_push_feature_si_exige_trivy(self):
        self.colocar_limpios(dependency_check=None, trivy=None)
        codigo, _, _ = self.ejecutar("--required", "semgrep,codeql,spotbugs,trivy")
        self.assertEqual(codigo, 2)

    def test_tabla_con_un_hallazgo_por_herramienta(self):
        self.colocar(
            semgrep="semgrep_rojo.sarif",
            codeql="codeql_rojo.sarif",
            spotbugs="spotbugs_rojo.xml",
            dependency_check="dc_rojo.json",
            trivy="trivy_sbom_rojo.json",
        )
        codigo, resumen, _ = self.ejecutar("--needs-json", json.dumps(NEEDS_OK))
        self.assertEqual(codigo, 1)
        self.assertIn("BLOQUEADO", resumen)
        tabla = resumen.split("### Hallazgos bloqueantes", 1)[1].split("###", 1)[0]
        for herramienta in ("semgrep", "codeql", "spotbugs", "dependency-check", "trivy"):
            self.assertIn(f"| {herramienta} |", tabla)

    def test_reportes_limpios_aprueba(self):
        self.colocar_limpios()
        codigo, resumen, _ = self.ejecutar("--needs-json", json.dumps(NEEDS_OK))
        self.assertEqual(codigo, 0)
        self.assertIn("APROBADO", resumen)

    def test_needs_json_desde_archivo(self):
        self.colocar_limpios()
        ruta = self.dir / "needs.json"
        ruta.write_text(json.dumps(NEEDS_OK), encoding="utf-8")
        codigo, _, _ = self.ejecutar("--needs-json", str(ruta))
        self.assertEqual(codigo, 0)

    def test_herramienta_desconocida_falla_cerrado(self):
        codigo, _, _ = self.ejecutar("--required", "sonar")
        self.assertEqual(codigo, 2)


class TestImagen(BaseGate):
    def test_libreria_o_so_corregible_high_bloquea(self):
        self.colocar(trivy_imagen_os="trivy_imagen_os_high.json", trivy_imagen_app="trivy_imagen_app_limpio.json")
        codigo, resumen, _ = self.ejecutar("--only", "trivy-imagen")
        self.assertEqual(codigo, 1)
        self.assertIn("CVE-2099-1000", resumen)

    def test_so_sin_correccion_filtrado_no_bloquea(self):
        # La pasada del SO llega ya filtrada por --ignore-unfixed: sin vulnerabilidades.
        self.colocar(trivy_imagen_os="trivy_imagen_os_limpio.json", trivy_imagen_app="trivy_imagen_app_limpio.json")
        codigo, resumen, _ = self.ejecutar("--only", "trivy-imagen")
        self.assertEqual(codigo, 0)
        self.assertIn("APROBADO", resumen)

    def test_imagen_exige_las_dos_pasadas(self):
        self.colocar(trivy_imagen_os="trivy_imagen_os_limpio.json")
        codigo, resumen, _ = self.ejecutar("--only", "trivy-imagen")
        self.assertEqual(codigo, 2)
        self.assertIn("trivy-imagen-app.json", resumen)


class TestEndurecimiento(BaseGate):
    """Casos de endurecimiento: CVSS v4/v2, jobs cancelados, entradas inválidas e inyección."""

    def escribir(self, nombre, datos):
        ruta = self.dir / nombre
        ruta.parent.mkdir(parents=True, exist_ok=True)
        ruta.write_text(json.dumps(datos), encoding="utf-8")
        return ruta

    def test_dependency_check_cvssv4_y_cvssv2(self):
        """Puntuación en cvssv4.cvssData (DC 12+) o solo severidad v2 HIGH: ambos bloquean."""
        ruta = self.escribir("dc.json", {"dependencies": [{
            "fileName": "x.jar",
            "vulnerabilities": [
                {"name": "CVE-V4", "cvssv4": {"cvssData": {"baseScore": 8.7}}},
                {"name": "CVE-V2", "severity": "HIGH", "cvssv2": {"score": 6.9}},
                {"name": "CVE-MEDIA", "severity": "MEDIUM", "cvssv3": {"baseScore": 6.5}},
            ],
        }]})
        hallazgos = {f.rule: f for f in qg.DependencyCheckParser().parse(ruta)}
        self.assertTrue(hallazgos["CVE-V4"].blocking)
        self.assertTrue(hallazgos["CVE-V2"].blocking)
        self.assertFalse(hallazgos["CVE-MEDIA"].blocking)

    def test_job_cancelado_bloquea(self):
        self.colocar_limpios()
        needs = dict(NEEDS_OK, **{"sast-codeql": {"result": "cancelled", "outputs": {}}})
        codigo, _, _ = self.ejecutar("--needs-json", json.dumps(needs))
        self.assertEqual(codigo, 1)

    def test_needs_json_invalido_falla_cerrado(self):
        self.colocar_limpios()
        codigo, _, _ = self.ejecutar("--needs-json", "{no es json")
        self.assertEqual(codigo, 2)

    def test_datos_del_reporte_no_inyectan_comandos_ni_markdown(self):
        """Un nombre de paquete con salto de línea no crea otro comando ::...:: ni rompe la tabla."""
        self.colocar_limpios(trivy=None)
        self.escribir(NOMBRES["trivy"], {"SchemaVersion": 2, "Results": [{
            "Target": "Java",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2099-0001", "Severity": "HIGH",
                "PkgName": "lib`x\n::warning::inyectado|col", "InstalledVersion": "1.0",
            }],
        }]})
        codigo, resumen, salida = self.ejecutar()
        self.assertEqual(codigo, 1)
        self.assertNotIn("\n::warning::", salida)
        self.assertIn("%0A::warning::inyectado", salida)
        fila = [l for l in resumen.splitlines() if "CVE-2099-0001" in l][0]
        self.assertNotIn("lib`x", fila)
        self.assertIn("inyectado\\|col", fila)


if __name__ == "__main__":
    unittest.main()
