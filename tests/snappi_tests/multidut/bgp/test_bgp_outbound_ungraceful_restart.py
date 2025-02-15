import pytest
import logging
from tests.common.helpers.assertions import pytest_require, pytest_assert                            # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts_multidut                                                                     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api, multidut_snappi_ports_for_bgp                                                       # noqa: F401
from tests.snappi_tests.variables import t1_t2_device_hostnames                                     # noqa: F401
from tests.snappi_tests.multidut.bgp.files.bgp_outbound_helper import (
     get_hw_platform, run_bgp_outbound_ungraceful_restart, run_dut_configuration)                   # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams                           # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]

ITERATION = 1
ROUTE_RANGES = [{
                    'IPv4': [
                        ['100.1.1.1', 24, 15000],
                        ['200.1.1.1', 24, 15000]
                    ],
                    'IPv6': [
                        ['5000::1', 64, 15000],
                        ['4000::1', 64, 15000]
                    ],
                }]


def test_dut_configuration(multidut_snappi_ports_for_bgp,                  # noqa: F811
                           conn_graph_facts,                             # noqa: F811
                           fanout_graph_facts_multidut,                  # noqa: F811
                           duthosts):                                       # noqa: F811
    """
    Configures BGP in T1, T2 Uplink and T2 Downlink

    Args:
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.test_name = "Dut Configuration"

    ansible_dut_hostnames = []
    for duthost in duthosts:
        ansible_dut_hostnames.append(duthost.hostname)

    hw_platform = get_hw_platform(ansible_dut_hostnames)
    if hw_platform is None:
        pytest_require(False, "Unable to get the hardware platform")

    logger.info("hw_platform: {}".format(hw_platform))
    for device_hostname in t1_t2_device_hostnames[hw_platform]:
        if device_hostname not in ansible_dut_hostnames:
            logger.info('!!!!! Attention: {} not in : {} derived from ansible dut hostnames'.
                        format(device_hostname, ansible_dut_hostnames))
            pytest_assert(False, "Mismatch between the dut hostnames in ansible and in variables.py files")

    for duthost in duthosts:
        if t1_t2_device_hostnames[hw_platform][0] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost1 = duthost
        elif t1_t2_device_hostnames[hw_platform][1] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost2 = duthost
        elif t1_t2_device_hostnames[hw_platform][2] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost3 = duthost
        else:
            continue
    snappi_extra_params.multi_dut_params.hw_platform = hw_platform
    snappi_extra_params.multi_dut_params.multi_dut_ports = multidut_snappi_ports_for_bgp
    run_dut_configuration(snappi_extra_params)


def test_bgp_outbound_uplink_ungraceful_restart(snappi_api,                                     # noqa: F811
                                                multidut_snappi_ports_for_bgp,                  # noqa: F811
                                                conn_graph_facts,                             # noqa: F811
                                                fanout_graph_facts_multidut,                  # noqa: F811
                                                duthosts,
                                                creds):                                # noqa: F811

    """
    Gets the packet loss duration on issuing ungraceful restart in uplink

    Args:
        snappi_api (pytest fixture): SNAPPI session
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.test_name = "Uplink Ungraceful Re-start"

    ansible_dut_hostnames = []
    for duthost in duthosts:
        ansible_dut_hostnames.append(duthost.hostname)

    hw_platform = get_hw_platform(ansible_dut_hostnames)
    if hw_platform is None:
        pytest_require(False, "Unknown HW Platform")
    logger.info("HW Platform: {}".format(hw_platform))

    for device_hostname in t1_t2_device_hostnames[hw_platform]:
        if device_hostname not in ansible_dut_hostnames:
            logger.info('!!!!! Attention: {} not in : {} derived from ansible dut hostnames'.
                        format(device_hostname, ansible_dut_hostnames))
            pytest_assert(False, "Mismatch between the dut hostnames in ansible and in variables.py files")

    for duthost in duthosts:
        if t1_t2_device_hostnames[hw_platform][0] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost1 = duthost
        elif t1_t2_device_hostnames[hw_platform][1] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost2 = duthost
        elif t1_t2_device_hostnames[hw_platform][2] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost3 = duthost
        elif t1_t2_device_hostnames[hw_platform][3] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost4 = duthost
        else:
            continue

    snappi_extra_params.device_name = t1_t2_device_hostnames[hw_platform][1]
    snappi_extra_params.multi_dut_params.hw_platform = hw_platform
    snappi_extra_params.multi_dut_params.multi_dut_ports = multidut_snappi_ports_for_bgp

    run_bgp_outbound_ungraceful_restart(api=snappi_api,
                                        creds=creds,
                                        is_supervisor=False,
                                        snappi_extra_params=snappi_extra_params)


def test_bgp_outbound_downlink_ungraceful_restart(snappi_api,                                     # noqa: F811
                                                  multidut_snappi_ports_for_bgp,                  # noqa: F811
                                                  conn_graph_facts,                             # noqa: F811
                                                  fanout_graph_facts_multidut,                  # noqa: F811
                                                  duthosts,
                                                  creds):                                # noqa: F811

    """
    Gets the packet loss duration on issuing ungraceful restart in downlink

    Args:
        snappi_api (pytest fixture): SNAPPI session
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.test_name = "Downlink Ungraceful Re-start"

    ansible_dut_hostnames = []
    for duthost in duthosts:
        ansible_dut_hostnames.append(duthost.hostname)

    hw_platform = get_hw_platform(ansible_dut_hostnames)
    if hw_platform is None:
        pytest_require(False, "Unknown HW Platform")
    logger.info("HW Platform: {}".format(hw_platform))

    for device_hostname in t1_t2_device_hostnames[hw_platform]:
        if device_hostname not in ansible_dut_hostnames:
            logger.info('!!!!! Attention: {} not in : {} derived from ansible dut hostnames'.
                        format(device_hostname, ansible_dut_hostnames))
            pytest_assert(False, "Mismatch between the dut hostnames in ansible and in variables.py files")

    for duthost in duthosts:
        if t1_t2_device_hostnames[hw_platform][0] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost1 = duthost
        elif t1_t2_device_hostnames[hw_platform][1] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost2 = duthost
        elif t1_t2_device_hostnames[hw_platform][2] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost3 = duthost
        elif t1_t2_device_hostnames[hw_platform][3] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost4 = duthost
        else:
            continue

    snappi_extra_params.device_name = t1_t2_device_hostnames[hw_platform][2]
    snappi_extra_params.multi_dut_params.hw_platform = hw_platform
    snappi_extra_params.multi_dut_params.multi_dut_ports = multidut_snappi_ports_for_bgp

    run_bgp_outbound_ungraceful_restart(api=snappi_api,
                                        creds=creds,
                                        is_supervisor=False,
                                        snappi_extra_params=snappi_extra_params)


def test_bgp_outbound_supervisor_ungraceful_restart(snappi_api,                                     # noqa: F811
                                                    multidut_snappi_ports_for_bgp,                  # noqa: F811
                                                    conn_graph_facts,                             # noqa: F811
                                                    fanout_graph_facts_multidut,                  # noqa: F811
                                                    duthosts,
                                                    creds):                                # noqa: F811

    """
    Gets the packet loss duration on issuing ungraceful restart in supervisor

    Args:
        snappi_api (pytest fixture): SNAPPI session
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.test_name = "Supervisor Ungraceful Re-start"

    ansible_dut_hostnames = []
    for duthost in duthosts:
        ansible_dut_hostnames.append(duthost.hostname)

    hw_platform = get_hw_platform(ansible_dut_hostnames)
    if hw_platform is None:
        pytest_require(False, "Unknown HW Platform")
    logger.info("HW Platform: {}".format(hw_platform))

    for device_hostname in t1_t2_device_hostnames[hw_platform]:
        if device_hostname not in ansible_dut_hostnames:
            logger.info('!!!!! Attention: {} not in : {} derived from ansible dut hostnames'.
                        format(device_hostname, ansible_dut_hostnames))
            pytest_assert(False, "Mismatch between the dut hostnames in ansible and in variables.py files")

    for duthost in duthosts:
        if t1_t2_device_hostnames[hw_platform][0] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost1 = duthost
        elif t1_t2_device_hostnames[hw_platform][1] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost2 = duthost
        elif t1_t2_device_hostnames[hw_platform][2] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost3 = duthost
        elif t1_t2_device_hostnames[hw_platform][3] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost4 = duthost
        else:
            continue

    snappi_extra_params.device_name = t1_t2_device_hostnames[hw_platform][3]
    snappi_extra_params.multi_dut_params.hw_platform = hw_platform
    snappi_extra_params.multi_dut_params.multi_dut_ports = multidut_snappi_ports_for_bgp

    run_bgp_outbound_ungraceful_restart(api=snappi_api,
                                        creds=creds,
                                        is_supervisor=True,
                                        snappi_extra_params=snappi_extra_params)
