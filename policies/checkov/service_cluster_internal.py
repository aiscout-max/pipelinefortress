"""Staging Services must stay cluster-internal (ClusterIP).

The staging deployment is reached only through `kubectl port-forward` inside
the CI runner. A NodePort or LoadBalancer would expose a deliberately
vulnerable app beyond the lab.
"""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check


class ServiceIsClusterInternal(BaseK8Check):
    def __init__(self):
        super().__init__(
            name="Service must be ClusterIP (no NodePort or LoadBalancer exposure)",
            id="CKV_PF_K8S_2",
            categories=[CheckCategories.NETWORKING],
            supported_entities=["Service"],
        )

    def scan_spec_conf(self, conf):
        service_type = (conf.get("spec") or {}).get("type", "ClusterIP")
        return CheckResult.PASSED if service_type == "ClusterIP" else CheckResult.FAILED


check = ServiceIsClusterInternal()
