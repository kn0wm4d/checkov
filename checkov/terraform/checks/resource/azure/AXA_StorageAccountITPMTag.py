from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class AXA_StorageAccountITPMTag(BaseResourceCheck):
    def __init__(self):
        description = "Ensure that resources are created with the ITPM tag"
        id = "AXA_AZURE_133"
        supported_resources = ['azurerm_storage_account']

        # Valid CheckCategories are defined in checkov/common/models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=description, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'tags' in conf.keys():
            for tag_list in conf.values():
                for tag in tag_list:
                    if "local-itpm" in tag.keys():
                        if len(tag["local-itpm"]) > 0:
                            return CheckResult.PASSED
        return CheckResult.FAILED


check = AXA_StorageAccountITPMTag()