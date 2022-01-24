# acl_mngt
Parse acl config as string, generate vendor specific config.

Install package:
```
pip3 install acl_mngt
```

Code example:
```
from acl_mngt import *
acl = """allow ingress 1.2.3.4/30
    allow ingress 1.2.3.8
    deny egress 2.2.3.4/30
    deny egress 2.2.3.8"""

af = AclFactory(acl, '192.168.1.0/24', ['172.16.8.0/24'])
af.render('cisco')

# Output: 
# ip:inacl#10=allow ip 192.168.1.0 0.0.0.255 1.2.3.4 0.0.0.3
# ip:inacl#11=allow ip 192.168.1.0 0.0.0.255 host 1.2.3.8
# ip:inacl#12=deny ip 2.2.3.4 0.0.0.3 192.168.1.0 0.0.0.255
# ip:inacl#13=deny ip host 2.2.3.8 192.168.1.0 0.0.0.255
# ip:inacl#14=allow ip 172.16.8.0 0.0.0.255 1.2.3.4 0.0.0.3
# ip:inacl#15=allow ip 172.16.8.0 0.0.0.255 host 1.2.3.8
# ip:inacl#16=deny ip 2.2.3.4 0.0.0.3 172.16.8.0 0.0.0.255
# ip:inacl#17=deny ip host 2.2.3.8 172.16.8.0 0.0.0.255
# ip:inacl#18=deny ip any any
```

Exception example, typo in `in(n)gress`:
```
acl = """allow inngress 1.2.3.4/30"""
af = AclFactory(acl, '192.168.1.0/24')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/local/lib/python3.9/site-packages/acl_mngt.py", line 196, in __init__
    raise ValueError(str(e) + f" on line {line}.") from None
ValueError: Not a valid ACL:
'allow inngress 1.2.3.4/30'
       ^ error at character 6 on line 1.
```
