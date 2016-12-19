gluon-radv-filterd
==================
This package drops all incoming router advertisements except for the
default router with the best metric according to B.A.T.M.A.N. advanced.

Note that advertisements originating from the node itself (for example
via gluon-radvd) are not affected and considered at all.

"Best" router
-------------
The best router is determined by the TQ that is reported for its originator by
B.A.T.M.A.N. advanced. If, for some reason, another gateway with a better TQ
appears or an existing gateway increases its TQ above that of the chosen
gateway, the chosen gateway will remain selected until the better gateway has a
TQ value at least X higher than the selected gateway. This is called
hysteresis, and X can be specified on the commandline/via UCI/the site.conf and
defaults to 20 (just as for the IPv4 gateway selection feature built into
B.A.T.M.A.N. advanced).
