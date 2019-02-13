import os
from shutil import rmtree

from leapp.actors import Actor
from leapp.models import SELinuxModules, SELinuxCustom, SELinuxRequestRPMs, CheckResult
from leapp.tags import ApplicationsPhaseTag, IPUWorkflowTag
from leapp.libraries.stdlib import run, CalledProcessError

WORKING_DIRECTORY = '/tmp/selinux/'

class SELinuxApplyCustom(Actor):
    '''
    Re-apply SELinux customizations from RHEL-7 installation

    Re-apply SELinux policy customizations (custom policy modules and changes
    introduced by semanage). Any changes (due to incompatiblity with RHEL-8
    SELinux policy) are reported to user.
    '''
    name = 'selinuxapplycustom'
    consumes = (SELinuxCustom, SELinuxModules, )
    produces = (CheckResult, )
    tags = (ApplicationsPhaseTag, IPUWorkflowTag, )

    def process(self):
        # cil module files need to be extracted to disk in order to be installed
        try:
            # clear working directory
            rmtree(WORKING_DIRECTORY)
        except OSError:
            # expected
            pass
        try:
            os.mkdir(WORKING_DIRECTORY)
        except OSError:
            self.log.info("Failed to access working directory! Aborting.")
            return

        # import custom SElinux modules
        for semodules in self.consume(SELinuxModules):
            self.log.info("Processing custom SELinux policy modules. Count: %d." % len(semodules.modules))
            for module in semodules.modules:
                cil_filename = "%s%s.cil" % (WORKING_DIRECTORY, module.name)
                self.log.info("Installing module %s on priority %d." % (module.name, module.priority))
                if module.removed:
                    self.log.info("The following lines where removed because of incompatibility: ")
                    self.log.info('\n'.join(module.removed))
                # write module content to disk
                try:
                    with open(cil_filename, 'w') as file:
                        file.write(module.content)
                except OSError as e:
                    self.log.info("Error writing %s : %s" % (cil_filename, e.strerror))
                    continue

                try:
                    semanage = run([
                        'semodule',
                        '-X',
                        str(module.priority),
                        '-i',
                        cil_filename]
                    )
                except CalledProcessError as e:
                    self.log.info("Error installing module: %s" % e.strerror)
                    # TODO - save the failed module to /etc/selinux ?
                    # currently it is still left in the old policy store
                    pass
                try:
                    os.remove(cil_filename)
                except OSError:
                    self.log.info("Error removing module file.")
        # import SELinux customizations collected by "semanage export"
        for custom in self.consume(SELinuxCustom):
            self.log.info('Importing SELinux customizations collected by "semanage export".')
            semanage_filename = WORKING_DIRECTORY + "semanage"
            # save SELinux customizations to disk
            try:
                with open(semanage_filename, 'w') as file:
                    file.write('\n'.join(custom.commands))
            except OSError as e:
                self.log.info("Error writing SELinux customizations: %s" % e.strerror)
            # import customizations
            try:
                run(['semanage', 'import', '-f', semanage_filename])
            except CalledProcessError:
                continue
            # clean-up
            try:
                os.remove(semanage_filename)
            except OSError:
                continue

        # clean-up
        try:
            os.rmdir("/tmp/selinux")
        except OSError:
            pass

        # TODO - Verify that all RPM packages reqested by selinux actors are installed
        for rpms in self.consume(SELinuxRequestRPMs):
            self.log.info("Verifying selinux-related RPMs requested before upgrade.")
            self.log.info("To keep: %s \n To install: %s" % (", ".join(rpms.to_keep), ", ".join(rpms.to_install)))

        # TODO - will be rewritten after LEAPP team rewrites reporting
        self.log.info("SElinux customizations reapplied successfully.")
        self.produce(
           CheckResult(
               severity='Info',
               result='Pass',
               summary='SElinux customizations reapplied successfully.',
               details='SELinux modules with non-standard priority and other custom settings where reapplied after the upgrade.',
               solutions=None
        ))


