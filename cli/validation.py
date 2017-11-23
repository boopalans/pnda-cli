#   Copyright (c) 2016 Cisco and/or its affiliates.
#   This software is licensed to you under the terms of the Apache License, Version 2.0
#   (the "License").
#   You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#   The code, technical concepts, and all information contained herein, are the property of
#   Cisco Technology, Inc.and/or its affiliated entities, under various laws including copyright,
#   international treaties, patent, and/or contract.
#   Any use of the material herein must be in accordance with the terms of the License.
#   All rights not expressly granted by the License are reserved.
#   Unless required by applicable law or agreed to separately in writing, software distributed
#   under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
#   ANY KIND, either express or implied.

import json
import re

import argparse
from argparse import RawTextHelpFormatter

def parse_user_input(flavors):

    epilog = """examples:
    - create new cluster, prompting for values:
    pnda-cli.py create
    - destroy existing cluster:
    pnda-cli.py destroy -e squirrel-land
    - expand existing cluster:
    pnda-cli.py expand -e squirrel-land -f standard -s keyname -n 10 -k 5
    Either, or both, kafka (k) and datanodes (n) can be changed. The value specifies the new total number of nodes. Shrinking is not supported - this must be done very carefully to avoid data loss.
        - create cluster without user input:
    pnda-cli.py create -s mykeyname -e squirrel-land -f standard -n 5 -o 1 -k 2 -z 3"""

    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description='PNDA CLI', epilog=epilog)

    parser.add_argument('command', help='Mode of operation', choices=['create', 'expand', 'destroy'])
    parser.add_argument('-e', '--pnda-cluster', type=Validator.format_validator_func("pnda_cluster"), help='Namespaced environment for machines in this cluster')
    parser.add_argument('-n', '--datanodes', type=Validator.format_validator_func("datanodes"), help='How many datanodes for the hadoop cluster')
    parser.add_argument('-o', '--opentsdb-nodes', type=Validator.format_validator_func("opentsdb_nodes"), help='How many Open TSDB nodes for the hadoop cluster')
    parser.add_argument('-k', '--kafka-nodes', type=Validator.format_validator_func("kafka_nodes"), help='How many kafka nodes for the databus cluster')
    parser.add_argument('-z', '--zk-nodes', type=Validator.format_validator_func("zk_nodes"), help='How many zookeeper nodes for the databus cluster')
    parser.add_argument('-f', '--flavor', help='PNDA flavor: "standard"', choices=flavors, default="standard")
    parser.add_argument('-s', '--keyname', help='Keypair name')
    parser.add_argument('-x', '--no-config-check', action='store_true', help='Skip config verifiction checks')
    parser.add_argument('-b', '--branch', help='Branch of platform-salt to use. Overrides value in pnda_env.yaml')
    parser.add_argument('-d', '--dry-run', action='store_true',
                        help='Output the final Cloud Formation template but do not apply it. ' +
                        'Useful for checking against the existing Cloud formation template to' +
                        'gain confidence before running the expand operation.')
    parser.add_argument('-m', '--x-machines-definition', help='Text file containing the IP addresses of existing machines to install PNDA on')

    args = parser.parse_args()

    return args

class Validator(object):
    
    name_regex = r"^[\.a-z0-9-]+$"
    name_validator = {"hint" : "may contain only a-z 0-9 and '-'"}
    integer_validator = {"hint" : "must be a positive integer"}
    identity_validator = {'func':lambda value: value,'hint':"any string"}

    def name_validator_func(name):
        if re.match(Validator.name_regex, name) is None:
            raise argparse.ArgumentTypeError(Validator.name_validator['hint'])
        return name
    name_validator['func'] = name_validator_func

    def integer_validator_func(val):
        try:
            as_num = int(val)
        except:
            raise argparse.ArgumentTypeError(Validator.integer_validator['hint'])
        return as_num
    integer_validator['func'] = integer_validator_func

    validators = {
        "pnda_cluster" : name_validator,
        "flavor" : identity_validator,
        "keyname": identity_validator,
        "datanodes" : integer_validator,
        "opentsdb_nodes" : integer_validator,
        "kafka_nodes" : integer_validator,
        "zk_nodes" : integer_validator
    }

    @staticmethod
    def format_validator_func(field):
        return Validator.validators[field]["func"]
    
    @staticmethod
    def format_validator_hint(field):
        return Validator.validators[field]["hint"]

    def __init__(self, flavor):
        self._rules = {}
        validation_file = open('/Users/trsmith2/dev/forks/pnda-cli/cloud-formation/%s/validation.json' % flavor)
        rules = json.load(validation_file)
        # apply same transformation applied by argparse library so rules are directly addressable
        for field, rule in rules.iteritems():
            self._rules[field.replace('-','_')] = rule
        self._mandatory = ['pnda_cluster', 'keyname', 'flavor']

    def _check_validation(self, restriction, value):
        if self._rules is None:
            return True

        if restriction.startswith("<="):
            return value <= int(restriction[2:])

        if restriction.startswith(">="):
            return value > int(restriction[2:])

        if restriction.startswith("<"):
            return value < int(restriction[1:])

        if restriction.startswith(">"):
            return value > int(restriction[1:])

        if "-" in restriction:
            restrict_min = int(restriction.split('-')[0])
            restrict_max = int(restriction.split('-')[1])
            return value >= restrict_min and value <= restrict_max

        return value == int(restriction)

    def get_validation_rule(self ,field):
        rule = None
        if self._rules is not None:
            rule = self._rules.get(field)
        return rule 

    def validate_field(self, field, value):
        restrictions = self.get_validation_rule(field)
        if restrictions is None: return True
        for restriction in restrictions.split(','):
            if self._check_validation(restriction, value):
                return True
        return False

    def validate(self, args):

        def prompt_user(field, val):
            hint = Validator.format_validator_hint(field)
            while val is None:
                suffix = " and be in range [%s]" % rule if rule is not None else ""
                val = raw_input("Please enter a value for %s (%s%s): " % (field, hint, suffix))
                try:
                    val = Validator.format_validator_func(field)(val)
                    if not self.validate_field(field, val):
                        print "'%s' is not in valid range (%s)" % (val, rule)
                        val = None
                except:
                    print "'%s' %s" % (field, hint)
                    val = None                            
            return val

        for field, val in args.iteritems():
            # range validate field if rule present
            rule = self.get_validation_rule(field)
            # if value is already specified, failing additional range check is considered fatal
            if val is not None:
                if not self.validate_field(field, val):
                    raise argparse.ArgumentTypeError("'%s' is not in valid range %s" % (val, rule))
            else:
                # if rule is specified or field is considered mandatory, prompt user until we have valid value
                if (rule is not None and rule != "0") or field in self._mandatory: 
                    val = prompt_user(field, val)
                # if rule is specified as zero and field is not specified, default to 0
                elif rule is not None and rule == "0":
                    val = 0 if val is None else val
            args[field] = val
        return args