#!/usr/bin/env python3

# Run as: ./program --interval 5 --mode lean
# Run as: ./program --interval 5 --mode classify --classify-base hex
# Run as: ./program --interval 5 --mode classify --classify-base hex --classify-level 2

## TODO: Test workflow and packet pipeline with OpenStack-mock
## TODO: Provisioning for classifiers
## TODO: For simplicity of the code, even for the lean model, we can store a provisioning pointing to the inserting chain
##       This can largely contribute to unify some of the functions that are currently split because of the models.
## TODO: Can we generalize lean as a classify 0-level ?
## TODO: What happens if killed during provisioning??

## TODO: Replace existing OpenStack rules to avoid looping all traffic through innefficiento firewall rules

import argparse
import logging
import os
import string
import time
import traceback
from contextlib import suppress

# Import our own iptables helper
from helpers_n_wrappers import iptc_helper3

# Define Neutron tables
CUSTOM_RAW_PRE  = "neutron-optimize-PREROUTING"
NEUTRON_RAW_PRE = "neutron-openvswi-PREROUTING"
NEUTRON_RAW_PRE_HOOK = "PREROUTING"
NEUTRON_RAW_PRE_HOOK_i = 1

CUSTOM_FILTER_FWD = "neutron-optimize-FORWARD"
NEUTRON_FILTER_FWD = "neutron-openvswi-FORWARD"
NEUTRON_FILTER_FWD_HOOK = "FORWARD"
NEUTRON_FILTER_FWD_HOOK_i = 1

# Read UUID from RAW_PRE table as it contains 1 extra char not available in FILTER_FWD
GENERATE_VM_CHAIN_NAME            = lambda x: "optimize-{}".format(x) if x else None
GENERATE_CLASSIFY_CHAIN_NAME_PRE  = lambda x: "classify-{}".format(x) if x else CUSTOM_RAW_PRE
GENERATE_CLASSIFY_CHAIN_NAME_FWD  = lambda x: "classify-{}".format(x) if x else CUSTOM_FILTER_FWD
GEN_NEUTRON_SG_INGRESS            = lambda x: "neutron-openvswi-i{}".format(x[:10])
GEN_NEUTRON_SG_EGRESS             = lambda x: "neutron-openvswi-o{}".format(x[:10])


def setup_logging_yaml(default_path='logging.yaml',
                       default_level=logging.INFO,
                       env_path='LOG_CFG',
                       env_level='LOG_LEVEL'):
    """Setup logging configuration"""
    path = os.getenv(env_path, default_path)
    level = os.getenv(env_level, default_level)
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=level)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Python OpenStack Firewall Optimizer v0.2')
    parser.add_argument('--interval', type=int, default=3,
                        help='Interval time for re-evaluation of rules')
    parser.add_argument('--classify-base', type=str, default='hex', choices=['dec', 'hex', 'alpha', 'alphanum'],
                        help='Classification base')
    parser.add_argument('--classify-level', type=int, default=0, choices=[0, 1, 2],
                        help='Classification levels')
    return parser.parse_args()


class OpenStackFirewallOptimizer(object):
    def __init__(self, args):
        # Store received arguments
        self.args = args
        self.logger = logging.getLogger('NeutronOptimizer')
        self.logger.info('Setup iptables provisioning')
        # Create provisioning
        self.setup_provisioning()


    def run(self):
        self.logger.info('Running!')
        self._t0 = time.time()
        self._nof_optimizations = 0
        while True:
            # Read current rules and filter UUIDs
            base_rules_d = self._collect_openstack_rules()
            base_uuid_d = self._process_openstack_rules(base_rules_d)
            self.logger.debug('> Found {} base VMs!'.format(len(base_uuid_d)))
            # Read currently optimized rules
            optimized_rules_d = self._collect_optimized_rules()
            optimized_uuid_d = self._process_optimized_rules(optimized_rules_d)
            self.logger.debug('> Found {} optimized VMs!'.format(len(optimized_uuid_d)))
            # Apply diff
            k = self._apply_optimized_rules(base_uuid_d, optimized_uuid_d)
            self._nof_optimizations += k
            if k:
                self.logger.info('> Added optimization for {} VMs!'.format(k))
            #input('Awaiting for next iteration...')
            time.sleep(args.interval)


    def cleanup(self):
        '''
        with suppress(Exception):
            # Cleanup existing optimized rules
            self._cleanup_optimized()
        with suppress(Exception):
            # Cleanup custom provisioning
            self.cleanup_custom_provisioning()
        '''
        self._cleanup_optimized()
        self.cleanup_custom_provisioning()

        t1 = time.time() - self._t0
        self.logger.warning('Optimized {} rules during {:.2f} sec uptime'.format(self._nof_optimizations, t1))
        self.logger.warning('## Terminating ##')


    def _cleanup_optimized(self):
        optimized_rules_d = self._collect_optimized_rules()
        optimized_uuid_d = self._process_optimized_rules(optimized_rules_d)
        self.logger.info('Removing existing optimized VMs!'.format(len(optimized_uuid_d)))
        self._apply_optimized_rules({}, optimized_uuid_d)


    def setup_provisioning(self):
        self.logger.info('Installing common provisioning')
        # Store key value of classifying uuid to chain, for each table
        self.provisioning_d = {'raw':{}, 'filter':{}}
        # Generate population base
        self.population = self._generate_population_base(self.args.classify_base)
        # Do custom provisioning based on optimization model
        self.logger.info('Installing optimization specific provisioning')
        self._generic_setup_provisioning(self.population, self.args.classify_level, '')
        # Insert hooks in raw and filter tables
        rule = {'in-interface':'qbr+', 'target':CUSTOM_RAW_PRE}
        iptc_helper3.add_rule('raw', NEUTRON_RAW_PRE_HOOK, rule, NEUTRON_RAW_PRE_HOOK_i, ipv6=False)
        rule = {'in-interface':'qbr+', 'target':CUSTOM_FILTER_FWD}
        iptc_helper3.add_rule('filter', NEUTRON_FILTER_FWD_HOOK, rule, NEUTRON_FILTER_FWD_HOOK_i, ipv6=False)


    def cleanup_custom_provisioning(self):
        self.logger.info('Cleanup common provisioning')
        # Cleanup hooks in raw and filter tables
        rule = {'in-interface':'qbr+', 'target':CUSTOM_RAW_PRE}
        iptc_helper3.delete_rule('raw', NEUTRON_RAW_PRE_HOOK, rule, ipv6=False)
        rule = {'in-interface':'qbr+', 'target':CUSTOM_FILTER_FWD}
        iptc_helper3.delete_rule('filter', NEUTRON_FILTER_FWD_HOOK, rule, ipv6=False)
        # Cleanup custom provisioning based on optimization model
        self.logger.info('Cleanup optimization specific provisioning')
        self._generic_cleanup_provisioning(self.population, self.args.classify_level, '')


    def _collect_openstack_rules(self):
        self.logger.debug('Collecting OpenStack rules')
        return iptc_helper3.dump_chain('raw', NEUTRON_RAW_PRE, ipv6=False)


    def _process_openstack_rules(self, rules):
        ''' Filtering capabilities are specific to OpenStack rules '''
        self.logger.debug('Processing OpenStack rules for UUIDs')
        uuid_d = {}
        # Iterate all rules and find unique uuids
        for rule in rules:
            # Use physdev match for compatibility with previous Neutron versions
            if 'physdev' not in rule:
                continue
            if 'physdev-in' not in rule['physdev']:
                continue
            _value = rule['physdev']['physdev-in']
            if _value.startswith('qvb') or _value.startswith('tap'):
                _uuid = _value[3:]
                uuid_d[_uuid] = rule
        return uuid_d


    def _collect_optimized_rules(self):
        self.logger.debug('Collecting optimized rules')
        rules_l = []
        # Use slice of raw table provisioning
        _provisioning = self.provisioning_d['raw']
        sorted_keys = sorted(_provisioning.keys())
        for k in sorted_keys:
            chain = _provisioning[k]
            rules_l += iptc_helper3.dump_chain('raw', chain, ipv6=False)
        return rules_l


    def _process_optimized_rules(self, rules):
        ''' Filtering capabilities are specific to our rules '''
        self.logger.debug('Processing optimized rules for UUIDs')
        uuid_d = {}
        # Iterate all rules and find unique uuids
        for rule in rules:
            if not 'in-interface' in rule or not rule['in-interface']:
                continue
            _value = rule['in-interface']
            if _value.startswith('qbr'):
                _uuid = rule['in-interface'][3:]
                uuid_d[_uuid] = rule
        return uuid_d

    def _lookup_chain_by_uuid(self, table, uuid_vm):
        # Trim uuid to current working depth
        level = self.args.classify_level
        _uuid = uuid_vm[:level]
        # Use slice of raw table provisioning
        _provisioning = self.provisioning_d[table]
        if _uuid not in _provisioning:
            self.logger.critical('Failed to lookup chain for UUID {}'.format(uuid_vm))
            return None
        return _provisioning[_uuid]

    def _apply_optimized_rules(self, default, optimized):
        ''' Receives dicts of (uuid, rule) and applies diff following simple optimization '''
        # Calculate new sets for added & removed
        default_s   = set(default.keys())
        optimized_s = set(optimized.keys())
        removed_s   = optimized_s - default_s
        added_s     = default_s - optimized_s

        if removed_s:
            self.logger.info('>> Remove old VM(s)! {}'.format(removed_s))
        if added_s:
            self.logger.info('>> Add new VM(s)! {}'.format(added_s))

        # Remove old entries
        for i, _uuid in enumerate(removed_s):
            self.logger.info('>> [#{}] Removing VM {}'.format(i+1, _uuid))
            vm_chain = GENERATE_VM_CHAIN_NAME(_uuid)
            _rule = optimized[_uuid]
            # Iterate insertion tables and do cleanup
            for table in ['raw', 'filter']:
                cl_chain = self._lookup_chain_by_uuid(table, _uuid)
                if not cl_chain:
                    self.logger.critical('UUID {} not found in base {}'.format(_uuid, self.args.classify_base))
                    continue
                # Delete trigger rule from classifying chain
                self.logger.debug('>>> delete rule: {}.{} {}'.format(table, cl_chain, _rule))
                iptc_helper3.delete_rule(table, cl_chain, _rule, ipv6=False)
                # Delete VM optimized chain
                self.logger.debug('>>> flush & delete chain: {}.{}'.format(table, vm_chain))
                iptc_helper3.flush_chain(table, vm_chain, ipv6=False)
                iptc_helper3.delete_chain(table, vm_chain, ipv6=False)

        # Add new entries
        for i, _uuid in enumerate(added_s):
            self.logger.info('>> [#{}] Adding VM {}'.format(i+1, _uuid))
            vm_chain = GENERATE_VM_CHAIN_NAME(_uuid)

            ### RAW TABLE ###
            # Select classifying table to insert triggers
            table = 'raw'
            cl_chain = self._lookup_chain_by_uuid(table, _uuid)
            if not cl_chain:
                self.logger.critical('UUID {} not found in base {}'.format(_uuid, self.args.classify_base))
                continue
            self.logger.debug('Selected classifying chain {}'.format(cl_chain))
            ## Create & populate VM optimized chain with simplest rules
            self.logger.debug('>>> add chain: {}.{}'.format(table, vm_chain))
            iptc_helper3.add_chain(table, vm_chain, ipv6=False)
            _rule = dict(default[_uuid])
            if 'physdev' in _rule:
                del _rule['physdev']
            if 'in-interface' in _rule:
                del _rule['in-interface']
            iptc_helper3.add_rule(table, vm_chain, _rule, ipv6=False)
            _rule = {'comment': {'comment': 'Accept early'}, 'target': 'ACCEPT'}
            iptc_helper3.add_rule(table, vm_chain, _rule, ipv6=False)

            ## Add trigger rule to classifying chain
            _rule = dict(default[_uuid])
            if 'physdev' in _rule:
                del _rule['physdev']
            _rule['in-interface'] = 'qbr{}'.format(_uuid)
            _rule['target'] = vm_chain
            self.logger.debug('>>> add rule: {}.{} {}'.format(table, cl_chain, _rule))
            iptc_helper3.add_rule(table, cl_chain, _rule, ipv6=False)

            ### FILTER TABLE ###
            # Select classifying table to insert triggers
            table = 'filter'
            cl_chain = self._lookup_chain_by_uuid(table, _uuid)
            if not cl_chain:
                self.logger.critical('UUID {} not found in base {}'.format(_uuid, self.args.classify_base))
                continue
            self.logger.debug('Selected classifying chain {}'.format(cl_chain))
            ## Create & populate VM optimized chain with simplest rules
            self.logger.debug('>>> add chain: {}.{}'.format(table, vm_chain))
            iptc_helper3.add_chain(table, vm_chain, ipv6=False)
            _rule = {'comment': {'comment': 'Jump to the VM specific chain.'},
                     'physdev': {'physdev-is-bridged': [], 'physdev-in': 'tap{}'.format(_uuid)},
                     'target': GEN_NEUTRON_SG_EGRESS(_uuid)}
            iptc_helper3.add_rule(table, vm_chain, _rule, ipv6=False)
            _rule = {'comment': {'comment': 'Jump to the VM specific chain.'},
                     'physdev': {'physdev-is-bridged': '', 'physdev-out': 'tap{}'.format(_uuid)},
                     'target': GEN_NEUTRON_SG_INGRESS(_uuid)}
            iptc_helper3.add_rule(table, vm_chain, _rule, ipv6=False)
            _rule = {'comment': {'comment': 'Accept early'}, 'target': 'ACCEPT'}
            iptc_helper3.add_rule(table, vm_chain, _rule, ipv6=False)

            ## Add trigger rule to classifying chain
            _rule = dict(default[_uuid])
            if 'physdev' in _rule:
                del _rule['physdev']
            _rule['in-interface'] = 'qbr{}'.format(_uuid)
            _rule['target'] = vm_chain
            self.logger.debug('>>> add rule: {}.{} {}'.format(table, cl_chain, _rule))
            iptc_helper3.add_rule(table, cl_chain, _rule, ipv6=False)

        # Return number of optimizations performed
        return len(added_s)


    def _generate_population_base(self, base):
        assert(base in ('dec', 'hex', 'alpha', 'alphanum'))
        # Build population
        if base == 'dec':
            population_l = ['{:d}'.format(i) for i in range(0,10)]
        elif base == 'hex':
            population_l = ['{:x}'.format(i) for i in range(0,16)]
        elif base == 'alpha':
            population_l = ['{:s}'.format(i) for i in string.ascii_lowercase]
        elif base == 'alphanum':
            population_l = ['{:s}'.format(i) for i in string.ascii_lowercase]
            population_l += ['{:d}'.format(i) for i in range(0,10)]
        return population_l


    def _whoami(self, table, token):
        if token:
            return 'classify-{}'.format(token)
        elif table == 'raw':
            return CUSTOM_RAW_PRE
        elif table == 'filter':
            return CUSTOM_FILTER_FWD


    def _generic_setup_provisioning(self, population, depth, token):
        '''
        Recursive function to walk tree structure for given depth and population, use carry-me-token for inner leafs
        Use token = ''   for building next level keys based on iterative concatenation of index keys
        Use token = None for building next level keys based on local index keys
        '''
        assert(depth >= 0)
        # Generate chain name based on tree position
        for table in ['raw', 'filter']:
            chain = self._whoami(table, token)
            iptc_helper3.add_chain(table, chain, ipv6=False, silent=False)
            iptc_helper3.flush_chain(table, chain, ipv6=False, silent=False)
            self.logger.debug('create&flush {}.{}'.format(table, chain))
            # Add records to classifier for fast indexing
            if depth == 0:
                self.provisioning_d[table][token] = chain

        if depth == 0:
            return

        # Walk towards each child, on return, link to them from the present chain
        for child in population:
            # Black magic for carry-me-token
            if token is not None:
                child = token_child = '{}{}'.format(token, child) # Recalculate new token and use as local key
            else:
                token_child = token                               # Carry same token to next level

            # Execute function for each children, before walking
            pass
            # Walk child
            self._generic_setup_provisioning(population, depth - 1, token_child)
            # Execute function for each children, after walking
            for table in ['raw', 'filter']:
                chain = self._whoami(table, token)
                target_chain = self._whoami(table, token_child)
                classify_rule = {'in-interface':'qbr{}+'.format(token_child), 'target': target_chain}
                self.logger.debug('add_rule / @{} {}'.format(chain, classify_rule))
                iptc_helper3.add_rule(table, chain, classify_rule, ipv6=False)


    def _generic_cleanup_provisioning(self, population, depth, token):
        '''
        Recursive function to walk tree structure for given depth and population, use carry-me-token for inner leafs
        Use token = ''   for building next level keys based on iterative concatenation of index keys
        Use token = None for building next level keys based on local index keys
        '''
        assert(depth >= 0)
        # Generate chain name based on tree position
        for table in ['raw', 'filter']:
            chain = self._whoami(table, token)
            if depth == 0:
                self.logger.debug('flush&delete {}.{}'.format(table, chain))
                iptc_helper3.flush_chain(table, chain, ipv6=False)
                iptc_helper3.delete_chain(table, chain, ipv6=False)
            else:
                self.logger.debug('flush {}.{}'.format(table, chain))
                iptc_helper3.flush_chain(table, chain, ipv6=False)

        if depth == 0:
            return

        # Walk towards each child, on return, link to them from the present chain
        for child in population:
            # Black magic for carry-me-token
            if token is not None:
                child = token_child = '{}{}'.format(token, child) # Recalculate new token and use as local key
            else:
                token_child = token                               # Carry same token to next level

            # Execute function for each children, before walking
            pass
            # Walk child
            self._generic_cleanup_provisioning(population, depth - 1, token_child)
            # Execute function for each children, after walking
            pass

        # Generate chain name based on tree position
        for table in ['raw', 'filter']:
            chain = self._whoami(table, token)
            iptc_helper3.flush_chain(table, chain, ipv6=False)
            iptc_helper3.delete_chain(table, chain, ipv6=False)
            self.logger.debug('flush&delete {}.{}'.format(table, chain))


if __name__ == "__main__":
    # Use function to configure logging from file
    setup_logging_yaml()
    logger = logging.getLogger(__name__)
    logger.info('## Starting Python OpenStack Iptables Optimizer v0.1 ##')
    # Parse arguments
    args = parse_arguments()
    try:
        # Instantiate object
        obj = OpenStackFirewallOptimizer(args)
        obj.run()
    except KeyboardInterrupt as e:
        logger.warning('Initiating graceful shutdown...')
        logger.critical(traceback.format_exc())
    except Exception as e:
        logger.critical('Unexpected Exception occured! {}'.format(e))
        logger.warning('Initiating graceful shutdown...')
        logger.critical(traceback.format_exc())
    finally:
        obj.cleanup()

    logger.info('## Terminated ##')
