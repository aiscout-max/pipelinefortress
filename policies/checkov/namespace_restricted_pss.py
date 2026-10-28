"""Every Namespace must enforce the `restricted` Pod Security Standard.

Checkov's built-in rules inspect each pod spec in isolation. This rule makes
the API server itself reject non-compliant pods, so a manifest that forgets a
securityContext fails at deploy time instead of running with defaults.
"""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check

LABEL = "pod-security.kubernetes.io/enforce"


class NamespaceEnforcesRestrictedPSS(BaseK8Check):
    def __init__(self):
        super().__init__(
            name="Namespace must enforce the restricted Pod Security Standard",
            id="CKV_PF_K8S_1",
            categories=[CheckCategories.KUBERNETES],
            supported_entities=["Namespace"],
        )

    def scan_spec_conf(self, conf):
        labels = (conf.get("metadata") or {}).get("labels") or {}
        return CheckResult.PASSED if labels.get(LABEL) == "restricted" else CheckResult.FAILED


check = NamespaceEnforcesRestrictedPSS()
