from leapp.actors import Actor
from leapp.models import SelinuxModules, SelinuxModule, SelinuxCustom, SystemFacts
from leapp.tags import FactsPhaseTag, IPUWorkflowTag
from leapp.libraries.stdlib import call
import subprocess
import re
import os



def parseSemodule(modules_str):
    """Parse list of modules into list of tuples (name,priority)"""
    modules = []
    for module in modules_str:
        m = re.match('([0-9]+)\s+(\w+)\s+(\w+)\s*\Z', module)
        if not m:
            #invalid output of "semodule -lfull"
            break
        modules.append((m.group(2), m.group(1)))

    return modules

def getSelinuxModules():
    try:
        semodule = call(['semodule', '-lfull'], split=True)
    except subprocess.CalledProcessError:
        return

    modules = parseSemodule(semodule)
    semodule_list = []

    # modules need to be extracted into cil files
    # cd to /tmp/selinux and save working directory so that we can return there
    wd = os.getcwd()
    os.mkdir("/tmp/selinux")
    os.chdir("/tmp/selinux")

    for (name, priority) in modules:
        if priority == "200":
            #TODO - request "name-selinux" to be installed
            continue
        if priority == "100":
            #module from selinux-policy-* package - skipping
            continue
        # extract custom module and save it to SelinuxModule object
        try:
            call(['semodule', '-c', '-X', priority, '-E', name])
            module_content = call(['cat', name + ".cil"], split=True)
            semodule_list.append(SelinuxModule(
                name=name,
                priority=int(priority),
                content=module_content
                )
            )
            # clean-up
            os.remove(name + ".cil")

        except subprocess.CalledProcessError:
            continue
    # clean-up
    os.rmdir("/tmp/selinux")
    os.chdir(wd)

    return semodule_list


class SelinuxContentScanner(Actor):
    name = 'selinuxcontentscanner'
    description = 'No description has been provided for the selinuxcontentscanner actor.'
    consumes = (SystemFacts, )
    produces = (SelinuxModules, SelinuxCustom, )
    tags = (FactsPhaseTag, IPUWorkflowTag, )

    def process(self):
        # exit if SELinux is disabled
        for fact in self.consume(SystemFacts):
            if fact.selinux.enabled is False:
                return

        semodule_list = getSelinuxModules()

        self.produce(SelinuxModules(modules=semodule_list))

        try:
            semanage = call(['semanage', 'export'], split=True)
        except subprocess.CalledProcessError:
            return

        self.produce(SelinuxCustom(commands=semanage))

        #cmd = [ 'semanage', 'export' ]
        #stdout = call(cmd, split=False)
        #semodules = SelinuxModules(
        #    modules=[SelinuxModule(
        #        name="nn",
        #        priority=1,
        #        content=stdout
        #)],)
        #self.produce(semodules)

