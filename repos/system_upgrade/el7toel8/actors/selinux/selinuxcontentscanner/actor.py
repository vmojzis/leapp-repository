from leapp.actors import Actor
from leapp.models import SelinuxModules, SelinuxModule, SystemFacts
from leapp.tags import FactsPhaseTag, IPUWorkflowTag
from leapp.libraries.stdlib import call

class Selinuxcontentscanner(Actor):
    name = 'selinuxcontentscanner'
    description = 'No description has been provided for the selinuxcontentscanner actor.'
    consumes = (SystemFacts)
    produces = (SelinuxModules,)
    tags = (FactsPhaseTag, IPUWorkflowTag)

    def process(self):
        for fact in self.consume(SystemFacts):
            if fact.selinux.enabled is False:
                return

        cmd = [ 'semanage', 'export' ]
        stdout = call(cmd)
        semodules = SelinuxModules(
            modules=SelinuxModule(
                name="nn",
                priority=1,
                content=stdout
        ),)
        self.produce(semodules)

