from leapp.models import Model, fields
from leapp.topics import SystemInfoTopic

class SelinuxModule(Model):
    """SELinux module in cil including priority"""
    topic = SystemInfoTopic
    name = fields.String()
    priority = fields.Integer()
    content = fields.List(fields.String())
    # lines removed due to content invalid on RHEL 8
    removed = fields.List(fields.String())

class SelinuxModules(Model):
    """List of custom selinux modules (priority != 100,200)"""
    topic = SystemInfoTopic
    modules = fields.List(fields.Model(SelinuxModule))

class SelinuxCustom(Model):
    """SELinux customizations returned by semanage export"""
    topic = SystemInfoTopic
    commands = fields.List(fields.String())

