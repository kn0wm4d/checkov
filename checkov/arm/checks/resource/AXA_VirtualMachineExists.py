from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_value_check import BaseResourceValueCheck

# https://docs.microsoft.com/en-us/azure/templates/microsoft.web/2019-08-01/sites


class AXA_VirtualMachineExists(BaseResourceValueCheck):
    def __init__(self):
        name = "Virtual Machines are not permitted in AXA's Azure Cloud environment."
        id = "AXA_AZURE_1"
        supported_resources = ['*']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources,
                         missing_block_result=CheckResult.FAILED)
    
    def scan_resource_conf(self, conf):
        inspected_key = self.get_inspected_key()
        expected_values = self.get_expected_values()
        if inspected_key in conf.keys():
            if conf[inspected_key] in expected_values:
                return CheckResult.FAILED

    def get_inspected_key(self):
        return 'type'

    def get_expected_value(self):
        return 'Microsoft.Compute/virtualMachines'


check = AXA_VirtualMachineExists()

