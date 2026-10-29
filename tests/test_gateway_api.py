"""Render an application using the local library, not a published dependency.

Run: helm dependency build charts/helmet --skip-refresh
     python3 -m unittest discover -s tests -v
Requires PyYAML. No Kubernetes cluster is needed.
"""
import copy
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
KINDS = ["HTTPRoute", "GRPCRoute", "TLSRoute", "TCPRoute", "UDPRoute"]


class GatewayAPITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.chart = Path(self.tmp.name)
        shutil.copytree(ROOT / "charts/helmet", self.chart / "charts/helmet")
        (self.chart / "Chart.yaml").write_text(yaml.safe_dump({
            "apiVersion": "v2", "name": "test-app", "version": "1.0.0",
            "dependencies": [{"name": "helmet", "version": "0.15.0",
                              "import-values": ["defaults"]}],
        }))
        (self.chart / "templates").mkdir()
        (self.chart / "templates/app.yaml").write_text('{{ include "helmet.app" . }}')

    def render(self, values=None, error=None):
        (self.chart / "values.yaml").write_text(yaml.safe_dump(values or {}))
        result = subprocess.run(
            ["helm", "template", "demo", str(self.chart), "--namespace", "apps"],
            text=True, capture_output=True,
        )
        if error:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(error, result.stderr)
            return []
        self.assertEqual(result.returncode, 0, result.stderr)
        return [doc for doc in yaml.safe_load_all(result.stdout) if doc]

    def test_defaults_disabled_routes_and_absent_configuration(self):
        for config in ({}, {"route": None, "gatewayAPI": None},
                       {"route": {"unused": {"enabled": False}}}):
            docs = self.render(config)
            self.assertFalse(any(d["kind"] in KINDS + ["BackendTLSPolicy"] for d in docs))
            self.assertIn("Service", [d["kind"] for d in docs])

    def test_all_route_kinds_and_metadata(self):
        config = {kind.lower(): {"kind": kind, "name": '{{ .Release.Name }}-' + kind.lower(),
                                "parentRefs": [{"name": "shared"}],
                                "rules": [{"backendRefs": [{"identifier": "app", "port": "http"}]}],
                                "labels": {"local": "yes"},
                                "annotations": {"shared": "local"}} for kind in KINDS}
        docs = self.render({"route": config, "namespaceOverride": "overridden",
                            "commonLabels": {"team": "platform"},
                            "commonAnnotations": {"shared": "global", "global": "yes"}})
        resources = [d for d in docs if d["kind"] in KINDS]
        self.assertEqual({d["kind"] for d in resources}, set(KINDS))
        for doc in resources:
            self.assertEqual(doc["apiVersion"], "gateway.networking.k8s.io/v1")
            self.assertEqual(doc["metadata"]["name"], "demo-" + doc["kind"].lower())
            self.assertEqual(doc["metadata"]["labels"]["team"], "platform")
            self.assertEqual(doc["metadata"]["labels"]["local"], "yes")
            self.assertEqual(doc["metadata"]["annotations"], {"shared": "local", "global": "yes"})
            self.assertEqual(doc["metadata"]["namespace"], "overridden")
            self.assertEqual(doc["spec"]["rules"][0]["backendRefs"],
                             [{"name": "demo-test-app", "port": 80}])

    def test_example_multiple_routes_and_explicit_backends(self):
        values = yaml.safe_load((ROOT / "charts/helmet/examples/gateway-api/values.yaml").read_text())
        second = copy.deepcopy(values["route"]["main"])
        second.update(name="other", namespace="{{ .Release.Namespace }}-other",
                      apiVersion="gateway.networking.k8s.io/v1beta1")
        # Explicit backends retain zero weights and native per-backend filters.
        external = {"name": "canary", "namespace": "external", "port": 8080, "weight": 0,
                    "filters": [{"type": "RequestHeaderModifier",
                                 "requestHeaderModifier": {"set": [{"name": "x-test", "value": "yes"}]}}]}
        second["rules"][0]["backendRefs"].append(external)
        values["route"]["secondary"] = second
        values["ingress"] = {"enabled": True}
        docs = self.render(values)
        self.assertIn("Ingress", [d["kind"] for d in docs])
        routes = [d for d in docs if d["kind"] == "HTTPRoute"]
        self.assertEqual(len(routes), 2)
        service = next(d for d in docs if d["kind"] == "Service")
        self.assertEqual(routes[0]["metadata"]["name"], service["metadata"]["name"] + "-main")
        self.assertEqual(routes[0]["spec"]["rules"][0]["backendRefs"],
                         [{"name": service["metadata"]["name"], "port": 80}])
        self.assertEqual(routes[1]["apiVersion"], "gateway.networking.k8s.io/v1beta1")
        self.assertEqual(routes[1]["metadata"]["namespace"], "apps-other")
        self.assertEqual(routes[1]["spec"]["rules"][0]["backendRefs"], [
            {"name": service["metadata"]["name"], "namespace": "apps", "port": 80}, external])
        self.assertEqual(routes[0]["spec"]["parentRefs"], [{
            "name": "shared-gateway", "namespace": "infrastructure", "sectionName": "https"}])
        self.assertFalse(any(d["kind"] in ("GatewayClass", "Gateway", "ReferenceGrant", "ListenerSet")
                             for d in docs))

    def test_service_port_resolution_and_errors(self):
        def config(backend):
            return {"route": {"main": {"rules": [{"backendRefs": [backend]}]}}}
        for port in ("http", 80, "{{ (first .Values.service.ports).port }}", None):
            backend = {"identifier": "app"}
            if port is not None:
                backend["port"] = port
            docs = self.render(config(backend))
            route = next(d for d in docs if d["kind"] == "HTTPRoute")
            self.assertEqual(route["spec"]["rules"][0]["backendRefs"],
                             [{"name": "demo-test-app", "port": 80}])
        self.render(config({"identifier": "other", "port": "http"}), error="unknown Service identifier")
        self.render(config({"identifier": "app", "port": "missing"}), error="not defined in service.ports")
        self.render(config({"identifier": "app", "port": "http", "name": "wrong"}),
                    error="cannot override backend")
        values = config({"identifier": "app"})
        values["service"] = {"ports": [{"name": "http", "port": 8080}, {"name": "metrics", "port": 9090}]}
        self.render(values, error="specify a backend port")
        values["route"]["main"]["rules"][0]["backendRefs"][0]["port"] = "metrics"
        route = next(d for d in self.render(values) if d["kind"] == "HTTPRoute")
        self.assertEqual(route["spec"]["rules"][0]["backendRefs"][0]["port"], 9090)
        values["service"]["ports"] = []
        self.render(values, error="requires the application Service")

    def test_native_redirect_rules_and_default_kind(self):
        spec = {"parentRefs": [{"name": "shared"}], "rules": [{"filters": [
            {"type": "RequestRedirect", "requestRedirect": {"scheme": "https", "statusCode": 301}}]}]}
        doc = next(d for d in self.render({"route": {"redirect": spec}}) if d["kind"] == "HTTPRoute")
        self.assertEqual(doc["spec"], spec)

    def test_invalid_kind_empty_spec_and_policy_required_fields(self):
        self.render({"route": {"main": {"kind": "Gateway"}}}, error="unsupported kind")
        self.render({"route": {"main": {}}}, error="requires a non-empty route spec")
        self.render({"gatewayAPI": {"backendTLSPolicies": [{"spec": {"validation": {}}}]}},
                    error="entries require a name")
        self.render({"gatewayAPI": {"backendTLSPolicies": [{"name": "tls"}]}},
                    error="requires a non-empty spec")

    def test_backend_tls_policy_targets_application_service(self):
        docs = self.render({"gatewayAPI": {"backendTLSPolicies": [{
            "name": "app-tls",
            "spec": {
                "targetRefs": [{"group": "", "kind": "Service",
                                "name": '{{ include "common.names.fullname" . }}'}],
                "validation": {"hostname": "app.internal.example.com",
                               "wellKnownCACertificates": "System"},
            },
        }]}})
        service = next(d for d in docs if d["kind"] == "Service")
        policy = next(d for d in docs if d["kind"] == "BackendTLSPolicy")
        self.assertEqual(policy["metadata"]["namespace"], service["metadata"]["namespace"])
        self.assertEqual(policy["spec"]["targetRefs"], [
            {"group": "", "kind": "Service", "name": service["metadata"]["name"]},
        ])
        self.assertEqual(policy["spec"]["validation"], {
            "hostname": "app.internal.example.com", "wellKnownCACertificates": "System",
        })

    def test_can_include_gateway_helper_directly(self):
        (self.chart / "templates/app.yaml").write_text('{{ include "helmet.gatewayAPI" . }}')
        self.assertEqual(self.render(), [])
        docs = self.render({"route": {"only": {
            "rules": [{"backendRefs": [{"name": "svc", "port": 80}]}]}}})
        self.assertEqual([d["kind"] for d in docs], ["HTTPRoute"])


if __name__ == "__main__":
    unittest.main()
