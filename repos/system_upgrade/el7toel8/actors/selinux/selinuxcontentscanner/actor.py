from leapp.actors import Actor


class Selinuxcontentscanner(Actor):
    name = 'selinuxcontentscanner'
    description = 'No description has been provided for the selinuxcontentscanner actor.'
    consumes = ()
    produces = (SelinuxModels)
    tags = ()

    def process(self):
        pass

