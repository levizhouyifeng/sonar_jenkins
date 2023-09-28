import logging
from . import ap

df = ap.AccessPoint()
log = logging.getLogger(__name__)


def first_step_of_pre_seq():
    return df.first_step_of_pre_seq()


def first_step_of_main_seq():
    return df.first_step_of_main_seq()


def initialize_connection():
    return df.initialize_connection()


def check_running_code():
    return df.check_running_code()


def assy_scan_info():
    return df.assy_scan_info()


def sysft_scan_info():
    return df.syft_scan_info()


def initialize_variables():
    return df.initialize_variables()


# def clear_arp_uut():
#     return df.clear_arp_uut()


def verify_sn_prefix():
    return df.verify_sn_prefix()


def area_check():
    return df.area_check()


def verify_lineid_sw_config():
    return df.verify_lineid_sw_config()


def test_image_check():
    return df.test_image_check()


def starting_test_cell():
    return df.starting_test_cell()


def add_tst_data_for_leading():
    return df.add_tst_data_for_leading()


def leading_finish():
    return df.leading_finish()


def poe_port_power_off():
    return df.poe_port_power_off()


def poe_port_power_on():
    return df.poe_port_power_on()


def add_tst_data_for_pre_seq():
    return df.add_tst_data_for_pre_seq()


def generate_top_sernum():
    return df.generate_top_sernum()


def pull_child_relation():
    return df.pull_child_relation(area='SYSASSY')


def finalization():
    return df.finalization()
