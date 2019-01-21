from leapp.actors import Actor
from leapp.models import SELinuxModules, SELinuxCustom,
from leapp.tags import FactsPhaseTag, IPUWorkflowTag
from leapp.libraries.stdlib import call
import subprocess
import os

WORKING_DIRECTORY = '/tmp/selinux/'


class SELinuxApplyCustom(Actor):
    name = 'selinuxapplycustom'
    description = 'No description has been provided for the selinuxcontentscanner actor.'
    consumes = (SELinuxCustom, SELinuxModules, )
    produces = (CheckResult, )
    # TODO replace by - tags = (ApplicationsPhaseTag, IPUWorkflowTag, )
    tags = (FactsPhaseTag, IPUWorkflowTag, )

    def process(self):
        # cil module files need to be extracted to disk in order to be installed
        try:
            os.mkdir(WORKING_DIRECTORY)
        except OSError:
            pass

        # exit if SELinux is disabled
        for semodules in self.consume(SELinuxModules):
            self.log.info("Processing " +
                len(semodules.modules) + "custom SELinux policy modules.")
            for module in semodules.modules:
                cil_filename = module.name + ".cil"
                self.log.info("Installing " + module.name
                 + " on priority " + module.priority + ".")
                if module.removed:
                    self.log.info("The following lines where removed because of incompatibility: ")
                    self.log.info('\n'.join(module.removed))
                # write module content to disk
                try:
                    with open(WORKING_DIRECTORY + cil_filename, 'w') as file:
                        file.write(module.content)
                except OSError as e:
                    self.log.info("Error writing " + cil_filename + " :" + e.strerror)
                    continue

                try:
                    semanage = call([
                        'semodule',
                        '-X',
                        str(module.priority),
                        '-i',
                        WORKING_DIRECTORY + cil_filename]
                    )
                except subprocess.CalledProcessError:
                    continue
                try:
                    os.remove(cil_filename)
                except OSError:
                    continue
        # TODO semanage import
        # clean-up
        try:
            os.rmdir("/tmp/selinux")
        except OSError:
            pass

        self.log.info("SElinux customizations reapplied successfully.")
        self.produce(
           CheckResult(
               severity='Info',
               result='Pass',
               summary='SElinux customizations reapplied successfully.',
               details='SELinux modules with non-standard priority and other custom settings where reapplied after the upgrade.',
               solutions=None
        ))


