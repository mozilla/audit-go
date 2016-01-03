#Linux Audit Heka Plugin (GO)

This project aims to deliver the same functionality as Linux Audit (auditd, audispd) + audisp-cef/json but in native Go as a plugin to Heka.

Currently the project listen for events from the kernel via the Netlink protocol and parse the messages and save them in `/tmp/log`.

Currently the Heka plugin is provided externally. Heka reads input using [Logstreamer](http://hekad.readthedocs.org/en/v0.10.0/config/inputs/logstreamer.html) from the file saved by `audit-go` and uses a custom lua decoder ([SandBoxed](http://hekad.readthedocs.org/en/v0.10.0/config/decoders/sandbox.html) decoder in Heka) defined in `audit_decoder.lua` which parses the audit messages and covert them to Heka Messages.

The messages are then converted to JSON format using [ESJsonEncoder](http://hekad.readthedocs.org/en/v0.10.0/config/encoders/esjson.html) of Heka.

To run with heka:

*   Move the decoder to decoders directory of Heka.

    `cp audit_decoder.lua /usr/share/heka/lua_decoders/`

*   Run heka with the config file `heka.toml`.

   `hekad -config=heka.toml`

*   You can change the config settings as per your convenience and enable additional outputs in Heka. For example, to feed the JSON messages to an Elasticsearch server, uncomment lines 68-73 in `heka.toml` (assuming the ES server is running on `localhost:9200`).

Goals:

*   To reduce complexity while integrating with log aggregation, visualization tools (eg. Kibana) and security tools (eg. MozDef).
*   Easier configuration and rule management.

###[Project Wiki](https://wiki.mozilla.org/Security/Mentorships/MWoS/2014/Linux_Audit_heka_plugin_%28Go%29)

Feedback
-----------------
Open an issue [https://github.com/mozilla/audit-go/issues](https://github.com/mozilla/audit-go/issues) to report a bug or request a new feature. Other comments and suggestions can be directly emailed to the authors.

