from leapp.models import Model, fields
from leapp.topics import SystemInfoTopic

class SelinuxModule(Model):
    topic = SystemInfoTopic
    name = fields.String()
    priority = fields.Integer()
    content = fields.String()


class SelinuxModules(Model):
    topic = SystemInfoTopic
    modules = fields.List(fields.Model(SelinuxModule))


