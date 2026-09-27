import unittest

from netcast3r.config import EgressConfig
from netcast3r.egress import ProxyPool


class ProxyPoolTests(unittest.TestCase):
    def test_no_proxies_returns_none(self):
        pool = ProxyPool(EgressConfig(user_proxies=[], use_public=False))
        self.assertIsNone(pool.get())

    def test_user_proxies_are_normalized(self):
        pool = ProxyPool(EgressConfig(user_proxies=["127.0.0.1:9000"], use_public=False))
        pool.ensure_loaded()
        self.assertEqual(len(pool._proxies), 1)
        self.assertEqual(pool._proxies[0].url, "http://127.0.0.1:9000")

    def test_mark_failed_evicts_proxy(self):
        pool = ProxyPool(EgressConfig(user_proxies=["127.0.0.1:9000"], use_public=False))
        pool.ensure_loaded()
        proxy = pool._proxies[0]
        proxy.alive = True
        pool.mark_failed(proxy.url)
        self.assertFalse(pool.get())


if __name__ == "__main__":
    unittest.main()
