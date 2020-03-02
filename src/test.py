# Standard example from: https://github.com/jruizgit/rules

from durable.lang import *

with ruleset('test'):
    # antecedent
    @when_all(m.subject == 'World')
    def say_hello(c):
        # consequent
        print ('Hello {0}'.format(c.m.subject))

post('test', { 'subject': 'World' })
