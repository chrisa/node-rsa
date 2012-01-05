import Options, Utils, sys
from os import unlink, symlink, popen
from os.path import exists, islink

srcdir = '.'
blddir = 'build'
VERSION = '0.0.1'

def set_options(ctx):
    ctx.tool_options('compiler_cxx')

def configure(ctx):
    ctx.check_tool('compiler_cxx')
    ctx.check_tool('node_addon')

def build(ctx):
    t = ctx.new_task_gen('cxx', 'shlib', 'node_addon')
    t.target = 'rsaBinding'
    t.source = 'node_rsa.cc'

def shutdown():
    t = 'rsaBinding.node'
    if Options.commands['clean']:
        if exists(t): unlink(t)
    if Options.commands['build']:
        if exists('build/default/' + t) and not exists(t):
            symlink('build/default/' + t, t)
        if exists('build/Release/' + t) and not exists(t):
            symlink('build/Release/' + t, t)
