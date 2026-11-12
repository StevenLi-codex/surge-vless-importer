import base64
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import convert as app

UUID = "00000000-0000-4000-8000-000000000001"
KEY = base64.urlsafe_b64encode(bytes(32)).decode().rstrip("=")
URI = "vless://%s@192.0.2.1:443?security=reality&type=tcp&sni=www.example.com&pbk=%s&sid=001122&flow=xtls-rprx-vision#Example" % (UUID, KEY)


def node(**updates):
    result = {"name": "Example", "type": "vless", "server": "192.0.2.1", "port": 443, "uuid": UUID, "tls": True}
    result.update(updates)
    return result


def converted(*nodes):
    return app.convert(json.dumps({"proxies": list(nodes)}))


class ConversionTests(unittest.TestCase):
    def test_reality_vision_uri_mapping(self):
        content = app.convert(URI)["content"]
        for expected in ("Example = vless, 192.0.2.1, 443", "username=" + UUID,
                         "flow=xtls-rprx-vision", "sni=www.example.com",
                         "reality-public-key=" + KEY, "reality-short-id=001122"):
            self.assertIn(expected, content)
        self.assertNotIn("[Proxy]", content)

    def test_base64_mixed_subscription(self):
        source = "trojan://other@example.com:443#Other\n" + URI
        for encoder in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encoder(source.encode()).decode().rstrip("=")
            self.assertEqual(app.convert(encoded)["count"], 1)

    def test_yaml_preserves_zero_prefixed_short_id_and_false(self):
        source = """proxies:
- name: Leading zero
  type: vless
  server: example.com
  port: 443
  uuid: my-user
  tls: true
  udp: false
  servername: www.example.com
  reality-opts:
    public-key: %s
    short-id: 001234
""" % KEY
        content = app.convert(source)["content"]
        self.assertIn("reality-short-id=001234", content)
        self.assertIn("udp-relay=false", content)

    def test_raw_unencrypted(self):
        content = converted(node(tls=False))["content"]
        self.assertNotIn("tls=", content)
        self.assertNotIn("flow=", content)

    def test_tcp_tls_and_vision(self):
        content = converted(node(flow="xtls-rprx-vision"))["content"]
        self.assertIn("tls=true", content)
        self.assertIn("flow=xtls-rprx-vision", content)

    def test_websocket_header_and_alpn_quoting(self):
        n = node(network="ws", alpn=["h2", "http/1.1"], **{"ws-opts": {"path": "/a,b", "headers": {"Host": "cdn.example.com", "X-Token": "a,b"}}})
        content = converted(n)["content"]
        self.assertIn('ws-path="/a,b"', content)
        self.assertIn('alpn="h2,http/1.1"', content)
        self.assertIn('ws-headers="Host:cdn.example.com|X-Token:a,b"', content)

    def test_grpc_uri(self):
        uri = "vless://%s@example.com:443?type=grpc&security=tls&serviceName=hello&mode=multi&authority=cdn.example.com#GRPC" % UUID
        content = app.convert(uri)["content"]
        for value in ("grpc=true", "grpc-service-name=hello", "grpc-mode=multi", "grpc-authority=cdn.example.com"):
            self.assertIn(value, content)

    def test_grpc_reality(self):
        result = app.convert(URI.replace("type=tcp", "type=grpc").replace("&flow=xtls-rprx-vision", ""))
        self.assertIn("grpc=true", result["content"])

    def test_ipv6_and_percent_encoded_name(self):
        result = app.convert("vless://%s@[2001:db8::1]:443?security=tls#%%E6%%B5%%8B%%E8%%AF%%95" % UUID)
        self.assertIn("测试 = vless, 2001:db8::1, 443", result["content"])

    def test_duplicate_names_disambiguated_and_duplicate_connections_removed(self):
        result = converted(node(), node(port=444), node(name="Another label"))
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["duplicates"], 1)
        self.assertIn("Example (2) =", result["content"])

    def test_unsupported_nodes_skipped_but_valid_kept(self):
        bad_nodes = [node(network="xhttp"), node(encryption="mlkem768x25519plus.test"),
                     node(network="ws", flow="xtls-rprx-vision"), node(network="grpc", tls=False),
                     node(network="ws", **{"ws-opts": {"max-early-data": 2048}})]
        result = converted(node(), *bad_nodes)
        self.assertEqual(result["count"], 1)
        self.assertEqual(len(result["warnings"]), 5)

    def test_reality_and_ws_not_silently_downgraded(self):
        with self.assertRaises(app.ConversionError):
            converted(node(network="ws", servername="example.com", **{"reality-opts": {"public-key": KEY}}))

    def test_other_protocols_ignored(self):
        self.assertEqual(converted(node(), {"name": "Other", "type": "ss"})["count"], 1)

    def test_malformed_inputs_fail(self):
        for source in ("", "not a subscription!", "<html>Denied</html>", "proxies: [", "proxies: []", "proxies: null"):
            with self.subTest(source=source):
                with self.assertRaises(app.ConversionError):
                    app.convert(source)

    def test_unsafe_yaml_tags_not_executed(self):
        with self.assertRaises(app.ConversionError):
            app.convert("!!python/object/apply:os.system ['touch /tmp/should-not-exist']")

    def test_recursive_yaml_rejected(self):
        with self.assertRaises(app.ConversionError):
            app.convert("proxies: &a [*a]")

    def test_incomplete_or_bad_reality_rejected(self):
        for fields in ({"public-key": "bad"}, {"public-key": KEY, "short-id": "xyz"}):
            with self.assertRaises(app.ConversionError):
                converted(node(servername="example.com", **{"reality-opts": fields}))

    def test_config_injection_rejected_or_normalized(self):
        with self.assertRaises(app.ConversionError):
            converted(node(server="x\n[Rule]"))
        with self.assertRaises(app.ConversionError):
            converted(node(uuid="id\nFINAL,DIRECT"))
        content = converted(node(name="A, B = C # D; E"))["content"]
        self.assertIn("A， B ＝ C ＃ D； E = vless", content)

    def test_ignored_fingerprint_options_reported(self):
        result = converted(node(servername="example.com", **{"client-fingerprint": "chrome", "reality-opts": {"public-key": KEY, "support-x25519mlkem768": True}}))
        self.assertEqual(len(result["notes"]), 2)
        self.assertNotIn("client-fingerprint=", result["content"])

    def test_output_deterministic(self):
        self.assertEqual(app.convert(URI)["content"], app.convert(URI)["content"])


class FileAndNetworkTests(unittest.TestCase):
    def test_cancel_input_or_preview_never_writes_output(self):
        for responses in ([KeyboardInterrupt()], [URI, KeyboardInterrupt()]):
            with self.subTest(stage=len(responses)):
                with patch.object(app, "applescript", side_effect=responses), patch.object(app, "write_list") as write:
                    with self.assertRaises(KeyboardInterrupt):
                        app.dialog_mode()
                    write.assert_not_called()

    def test_conf_write_forbidden_and_existing_file_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            profile = Path(d) / "自用.conf"
            profile.write_text("original profile")
            with self.assertRaises(app.ConversionError):
                app.write_list(profile, app.convert(URI)["content"])
            self.assertEqual(profile.read_text(), "original profile")

    def test_failed_conversion_leaves_previous_output(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "bad.yaml"
            source.write_text("proxies: []")
            output = Path(d) / "vless.list"
            output.write_text("previous valid nodes")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(app.main(["--source-file", str(source), "--output", str(output)]), 1)
            self.assertEqual(output.read_text(), "previous valid nodes")

    def test_local_file_conversion_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            source, output = Path(d) / "source.txt", Path(d) / "output" / "vless.list"
            source.write_text(URI)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(app.main(["--source-file", str(source), "--output", str(output)]), 0)
            self.assertIn("reality-public-key=", output.read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_symlink_output_refused(self):
        with tempfile.TemporaryDirectory() as d:
            profile, link = Path(d) / "profile.conf", Path(d) / "vless.list"
            profile.write_text("original")
            link.symlink_to(profile)
            with self.assertRaises(app.ConversionError):
                app.write_list(link, "new")
            self.assertEqual(profile.read_text(), "original")

    def test_http_fetch_and_error_redaction(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get("User-Agent"))
                if self.path.startswith("/bad"):
                    self.send_error(403)
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(base64.b64encode(URI.encode()))

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = "http://127.0.0.1:%d" % server.server_port
            with patch.dict("os.environ", {"no_proxy": "127.0.0.1"}):
                self.assertEqual(app.convert(app.read_source(base + "/nodes?token=secret"))["count"], 1)
                with self.assertRaises(app.ConversionError) as error:
                    app.read_source(base + "/bad?token=secret")
            self.assertEqual(seen[0], "clash.meta")
            self.assertNotIn("secret", str(error.exception))
            self.assertNotIn("127.0.0.1", str(error.exception))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_output_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "source.list"
            source.write_text(URI)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(app.main(["--source-file", str(source), "--output", str(source)]), 1)
            self.assertEqual(source.read_text(), URI)


if __name__ == "__main__":
    unittest.main()
