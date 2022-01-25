from acl_mngt import *
import pytest


def test_happy_flow_no_routed_subnets():
    acl = """allow ingress 1.2.3.4/30
allow ingress 1.2.3.8
deny egress 2.2.3.4/30
deny egress 2.2.3.8"""

    expected_output = """ip:inacl#10=allow ip 1.2.3.4 0.0.0.3 192.168.1.0 0.0.0.255
ip:inacl#11=allow ip host 1.2.3.8 192.168.1.0 0.0.0.255
ip:inacl#12=deny ip 192.168.1.0 0.0.0.255 2.2.3.4 0.0.0.3
ip:inacl#13=deny ip 192.168.1.0 0.0.0.255 host 2.2.3.8
ip:inacl#14=deny ip any any"""

    af = AclFactory(acl, '192.168.1.0/24', [])
    assert af.render('cisco') == expected_output


def test_happy_flow_one_routed_subnets():
    acl = """allow ingress 1.2.3.4/30
allow ingress 1.2.3.8
deny egress 2.2.3.4/30
deny egress 2.2.3.8"""

    expected_output = """ip:inacl#10=allow ip 1.2.3.4 0.0.0.3 192.168.1.0 0.0.0.255
ip:inacl#11=allow ip host 1.2.3.8 192.168.1.0 0.0.0.255
ip:inacl#12=deny ip 192.168.1.0 0.0.0.255 2.2.3.4 0.0.0.3
ip:inacl#13=deny ip 192.168.1.0 0.0.0.255 host 2.2.3.8
ip:inacl#14=allow ip 1.2.3.4 0.0.0.3 172.16.8.0 0.0.0.255
ip:inacl#15=allow ip host 1.2.3.8 172.16.8.0 0.0.0.255
ip:inacl#16=deny ip 172.16.8.0 0.0.0.255 2.2.3.4 0.0.0.3
ip:inacl#17=deny ip 172.16.8.0 0.0.0.255 host 2.2.3.8
ip:inacl#18=deny ip any any"""

    af = AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24'])
    assert af.render('cisco') == expected_output


def test_happy_flow_two_routed_subnets():
    acl = """# This is a comment, and I should not be rendered.
    allow ingress 1.2.3.4/30
 allow ingress 1.2.3.8
  # Halfway you can have comments too, I'm special, I have spaces before my hashtag
deny egress 2.2.3.4/30
deny egress 2.2.3.8
# I'm a trailing comment"""

    expected_output = """ip:inacl#10=allow ip 1.2.3.4 0.0.0.3 192.168.1.0 0.0.0.255
ip:inacl#11=allow ip host 1.2.3.8 192.168.1.0 0.0.0.255
ip:inacl#12=deny ip 192.168.1.0 0.0.0.255 2.2.3.4 0.0.0.3
ip:inacl#13=deny ip 192.168.1.0 0.0.0.255 host 2.2.3.8
ip:inacl#14=allow ip 1.2.3.4 0.0.0.3 172.16.8.0 0.0.0.255
ip:inacl#15=allow ip host 1.2.3.8 172.16.8.0 0.0.0.255
ip:inacl#16=deny ip 172.16.8.0 0.0.0.255 2.2.3.4 0.0.0.3
ip:inacl#17=deny ip 172.16.8.0 0.0.0.255 host 2.2.3.8
ip:inacl#18=allow ip 1.2.3.4 0.0.0.3 host 10.20.30.8
ip:inacl#19=allow ip host 1.2.3.8 host 10.20.30.8
ip:inacl#20=deny ip host 10.20.30.8 2.2.3.4 0.0.0.3
ip:inacl#21=deny ip host 10.20.30.8 host 2.2.3.8
ip:inacl#22=deny ip any any"""

    af = AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24', '10.20.30.8/32'])
    assert af.render('cisco') == expected_output


def test_typo_in_allow():
    acl = """allow ingress 1.2.3.4/30
alllow ingress 1.2.3.4
deny egress 1.2.3.4/30
deny egress 1.2.3.4"""

    with pytest.raises(ValueError, match=r".*error at character 0 on line 2.$"):
        AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24', '10.20.30.8/32'])


def test_typo_in_deny():
    acl = """allow ingress 1.2.3.4/30
allow ingress 1.2.3.4
ddeny egress 1.2.3.4/30
deny egress 1.2.3.4"""

    with pytest.raises(ValueError, match=r".*error at character 0 on line 3.$"):
        AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24', '10.20.30.8/32'])


def test_typo_in_ingress():
    acl = """allow ingress 1.2.3.4/30
allow inngress 1.2.3.4
deny egress 1.2.3.4/30
deny egress 1.2.3.4"""

    with pytest.raises(ValueError, match=r".*error at character 6 on line 2.$"):
        AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24', '10.20.30.8/32'])


def test_typo_in_egress():
    acl = """allow ingress 1.2.3.4/30
allow ingress 1.2.3.4
deny eeegress 1.2.3.4/30
deny egress 1.2.3.4"""

    with pytest.raises(ValueError, match=r".*error at character 5 on line 3.$"):
        AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24', '10.20.30.8/32'])


def test_typo_in_ip():
    acl = """allow ingress 1.2.3.4
allow ingress 1.2.3.4
deny egress 301.2.3.4/30
deny egress 301.2.3.4"""

    with pytest.raises(ValueError, match=r".*error at character 12 on line 3.$"):
        AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24', '10.20.30.8/32'])


def test_invalid_prefix_length():
    acl = """
        allow ingress 1.2.3.4
        allow ingress 1.2.3.4
        deny egress 1.2.3.4/33
        deny egress 1.2.3.4"""

    with pytest.raises(ValueError, match=r".*error at character 20 on line 4.$"):
        AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24', '10.20.30.8/32'])


def test_with_invalid_seperator_hashtag():
    acl = """
        allow ingress 1.2.3.4
        allow ingress 1.2.3.4
        deny egress 1.2.3.4#32
        deny egress 1.2.3.4"""

    with pytest.raises(ValueError, match=r".*error at character 12 on line 4.$"):
        AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24', '10.20.30.8/32'])


def test_with_invalid_seperator_doubleslash():
    acl = """
        allow ingress 1.2.3.4
        allow ingress 1.2.3.4
        deny egress 1.2.3.4//32
        deny egress 1.2.3.4"""

    with pytest.raises(ValueError, match=r".*error at character 20 on line 4.$"):
        AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24', '10.20.30.8/32'])
