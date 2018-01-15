#!/usr/bin/env python3

import argparse
import logging
import os
import random
import statistics
import string
import sys
import traceback
import uuid

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
    parser = argparse.ArgumentParser(description='Iptables Classification Tool v0.1')
    parser.add_argument('--provisioning', type=int, default=10,
                        help='Number of VMs')
    parser.add_argument('--base', type=str, default='hex', choices=('dec', 'hex', 'alpha', 'alphanum'),
                        help='Iptables classification base / decimal or hexadecimal')
    parser.add_argument('--distribution', type=str, default='uniform', choices=('random', 'uniform'),
                        help='Statistical distribution in use')
    parser.add_argument('--iterations', type=int, default=1,
                        help='Repeat tests a number of iterations when using random distribution')
    parser.add_argument('--depth', type=int, default=0, choices=[0, 1, 2, 3, 4, 5],
                        help='Number of classifying levels')
    parser.add_argument('--mode', required=True, type=str, default='default', choices=['default', 'classify'],
                        help='Evaluation mode [default, classify]')
    parser.add_argument('--log-file', type=str, default='ipt_classification.csv',
                        help='Outpug log file')
    parser.add_argument('--log-header', action='store_true',
                        help='Write csv header to log file')
    return parser.parse_args()


class FirewallStructureAnalyzer(object):
    def __init__(self, args):
        # Store received arguments
        self.args = args
        self.logger = logging.getLogger('FirewallStructureAnalyzer')
        self.logger.info('Setup firewall provisioning')
        # Sanity check argument parameters
        if self.args.mode == 'default' and self.args.depth != 0:
            self.logger.error('Incompatible <default> mode with selected <depth> value')
            sys.exit(1)


        if self.args.log_header:
            self.logger.info('Opening logfile {} with mode w+'.format(self.args.log_file))
            self.logfd = open(self.args.log_file, mode='w+')
            header  = 'name,provisioning,depth,base,iteration,distribution,min,max,mean,median,pstdev,stdev,sum'
            self.logger.info(header)
            print(header, file=self.logfd, flush=True)
        else:
            self.logger.info('Opening logfile {} with mode a+'.format(self.args.log_file))
            self.logfd = open(self.args.log_file, mode='a+')


    def _init_state(self):
        ''' Initialize state variables '''
        # Store key value of uuid level classifying to list of allocated elements
        self.provisioning_d = {}
        # Store all allocated elements in order of provisioning
        self.population_base = []
        self.population_l = []
        # Store computed list of results for math analysis
        self.result_l = []


    def run(self):
        # Run in loop the number of iterations
        for i in range(1, self.args.iterations + 1):
            # (re) initialize local state for each iteration
            self._init_state()
            self.setup_provisioning()
            self.compute_cost_calculation()
            #print(self.result_l)
            #print(self.population_l)
            # Generate statistical values based on result list
            r_pstdev = 0
            r_stdev = 0
            r_min = min(self.result_l)
            r_max = max(self.result_l)
            r_mean = statistics.mean(self.result_l)
            r_median = statistics.median(self.result_l)
            r_sum = sum(self.result_l)
            if len(self.result_l) > 1:
                r_pstdev = statistics.pstdev(self.result_l)
                r_stdev = statistics.stdev(self.result_l)
            # Create result to log
            name = '{}_{}'.format(self.args.mode, self.args.depth)
            toprint = '{},{},{},{},{},{},{},{},{},{},{},{},{}'.format(name, args.provisioning, args.depth, args.base, i, args.distribution,
                                                                      r_min, r_max, r_mean, r_median, r_pstdev, r_stdev, r_sum)
            self.logger.info(toprint)
            print(toprint, file=self.logfd, flush=True)


    def cleanup(self):
        self.logfd.close()
        pass


    def setup_provisioning(self):
        ''' Store population in a set and provision a dictionary with the population according to classification levels '''
        self.logger.debug('Creating provisioning')
        base = self.args.base

        # Generate pool of digits for alpha and alphanum bases
        self.population_base = self._generate_population_base(base)

        if self.args.distribution == 'random':
            n = 0
            while n < self.args.provisioning:
                if base == 'dec':
                    d = '{0:010d}'.format(uuid.uuid4().int % 10**10)
                elif base == 'hex':
                    d = uuid.uuid4().hex[-10:]
                elif base == 'alpha':
                    d = ''.join([random.choice(self.population_base) for _i in range(0,10)])
                elif base == 'alphanum':
                    d = ''.join([random.choice(self.population_base) for _i in range(0,10)])
                # Trim key according to the levels of classification
                key = d[:self.args.depth]
                # Add new element to population list
                self.population_l.append(d)
                # Create a list entry in the dictionary to store all related provisioning
                self.provisioning_d.setdefault(key, []).append(d)
                n+=1

        elif self.args.distribution == 'uniform':
            for n in range(0, self.args.provisioning):
                if base == 'dec':
                    d = '{0:010d}'.format(n)
                elif base == 'hex':
                    d = '{0:010x}'.format(n)
                elif base == 'alpha':
                    d = self._int_to_base(n, self.population_base).rjust(10, '0')
                elif base == 'alphanum':
                    d = self._int_to_base(n, self.population_base).rjust(10, '0')
                # Reverse number for uniform classification
                d = d[::-1]
                # Trim key according to the levels of classification
                key = d[:self.args.depth]
                # Add new element to population list
                self.population_l.append(d)
                # Create a list entry in the dictionary to store all related provisioning
                self.provisioning_d.setdefault(key, []).append(d)


    def compute_cost_calculation(self):
        # Calculate costs of current provisioning
        if self.args.mode == 'default':
            self._cost_default()
        elif self.args.mode == 'classify':
            self._cost_classify()


    def _cost_default(self):
        ''' Calculate cost for the current population following default OpenStack firewall model '''
        # This is the new calculation, based on each specific element of the population
        for i, element in enumerate(self.population_l):
            # Use natural indexing because of firewall rules evaluation
            i += 1
            ## raw.PREROUTING contains 3 rules per entry + 1 of policy, all are evaluated
            cost_raw_pre = 3 * args.provisioning + 1
            ## filter.FORWARD contains 2 nested chains, calculate separately
            ### filter.FORWARD chain 1 contains 2 rules per entry, use the 2nd match
            cost_filter_fwd_1 = 2 * i
            ### filter.FORWARD SG chain contains 2 rules per entry + 1 of policy, all are evaluated
            cost_filter_fwd_2 = 2 * args.provisioning + 1
            # Aggregate all costs
            total_cost = cost_raw_pre + cost_filter_fwd_1 + cost_filter_fwd_2
            # Add result
            self.result_l.append(total_cost)
            # Fine-grained logging
            self.logger.debug('[{}] raw.pre = {} /  filter.fwd = {}  /  total = {}'.format(i, cost_raw_pre, cost_filter_fwd_1 + cost_filter_fwd_2, total_cost))


    def _cost_classify(self):
        ''' Calculate cost for the current population following optimized classification model '''
        # This is the new calculation, based on each specific element of the population
        for i, element in enumerate(self.population_l):
            cost_lookup_chain = 0
            # Trim key according to the levels of classification
            key = element[:self.args.depth]
            for digit in key:
                # Find digit within the base list and + 1 for the traversing cost
                cost_lookup_chain += self.population_base.index(digit) + 1
            # Get list of elements for extracted key
            element_l = self.provisioning_d[key]
            # Calculate matching cost of element within the list
            cost_position = element_l.index(element) + 1
            ## raw.PREROUTING lookup costs + position cost + 2 rules in custom chain
            cost_raw_pre = cost_lookup_chain + cost_position + 2
            ## filter.FORWARD lookup costs + position cost + 3 rules in custom chain
            cost_filter_fwd = cost_lookup_chain + cost_position + 3
            # Aggregate all costs
            total_cost = cost_raw_pre + cost_filter_fwd
            # Add result
            self.result_l.append(total_cost)
            # Fine-grained logging
            self.logger.debug('[{}] raw.pre = {} /  filter.fwd = {}  /  total = {}'.format(i, cost_raw_pre, cost_filter_fwd, total_cost))


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
            population_l = ['{:d}'.format(i) for i in range(0,10)]
            population_l += ['{:s}'.format(i) for i in string.ascii_lowercase]
        return population_l


    def _int_to_base(self, number, pool):
        pool_len = len(pool)
        base_n = ''
        pos = 0
        while number > 0:
            digit = int((number / (pool_len ** pos)) % pool_len)
            char = pool[digit]
            base_n = '{}{}'.format(char, base_n)
            number -= digit * (pool_len ** pos)
            pos += 1
        return base_n


    def _int_from_base(self, number, pool):
        pool_len = len(pool)
        n = 0
        rev_number = number[::-1]
        for i, digit in enumerate(rev_number):
            n += pool.index(digit) * pool_len**i
        return n


if __name__ == "__main__":
    # Use function to configure logging from file
    setup_logging_yaml()
    logger = logging.getLogger(__name__)
    logger.info('## Starting Firewall Structure Analyzer v0.1 ##')
    # Parse arguments
    args = parse_arguments()
    try:
        # Instantiate object
        obj = FirewallStructureAnalyzer(args)
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
    sys.exit(1)
