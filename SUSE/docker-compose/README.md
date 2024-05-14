# Linux Security Sensor Deployment

## Summary

This document is intended to be a short guide to deploying the Linux Security Sensor.  It is almost certainly incomplete but will cover most of the basics.  If you encounter difficulties or there are inaccuracies, please contact the development team.

## Architecture

The Linux Security Sensor is designed to collect events and respond to queries from a central server. Each step in the communication process is intended to be reliable  in the event of a component or network becoming unavailable. The client will cache up to 1GB of events before dropping them. The [Velociraptor](https://docs.velociraptor.app/) logscale plugin on the server formats, and forwards them to Logscale for later consumption by the IT Security team.

In many deployments, the Velociraptor server is the interface used to consume the information provided by the client, but in this deployment it is intended for Logscale to be the primary interface for information consumption and Velociraptor is used primarily for configuration of endpoints and remote access during incident response.

## Docker Compose

There is a template `docker-compose.yml` contained in this repository. The defaults should be generally sane for a test deployment but work still needs to be done to use TLS within the container. For now, the traffic between containers is unencrypted but isolated within the network created for this compose environment.  The `docker-compose.yml` file can be used as-is but the user must copy `env.sample` to `.env` and fill in the missing values.

### Sensor Frontend

Source: SUSE built container

The `sensor-frontend` container holds the Velociraptor server. It requires a bit of configuration before startup.

This container exposes four ports, each of which are configurable within the `server.conf` file. This document assumes that the defaults used in the `server.conf` and `docker-compose.yml` files are unchanged. If different ports are required, the two files must be kept in sync.

- Frontend
	- Port 8000
	- This is the port that provides the interface for the endpoint clients to use to register themselves, send events, and receive commands from the server. It uses TLS using a self-signed internal CA and a static name of VelociraptorServer. Each client is configured to use this internal CA and the server is the only source of certificates. This port is exposed directly to the network.
- GUI:
	- Port 8889
	- This is the port that provides the administrative interface. It serves a React app for administrative management as well as the API endpoints to implement it. By default this uses the same TLS certificate that the Frontend uses, but that requires every user who accesses the GUI to also accept the internal certificate authority, which is awkward and unnecessary. Instead, we use a reverse proxy that obtains certificates already linked to the end user's trusted certificate list to avoid additional configuration. See [traefik](#traefik) below.
- Monitoring
	- Port 8003
	- This provides a way to gather runtime metrics that can be consumed by Prometheus or other similar monitoring tools. It is an unencrypted read-only interface and does not require authentication to access. In the default configuration this is not exposed to the outside network.
- API
	- Port 8001
	- This is the internal gRPC endpoint and does not need to be exposed to the network unless the server is operating in a large environment where multiple frontend servers are required.

The hostname and ports defined in the `sensor-frontend` block must match the ones used in the `server.conf` file.

### Sensor Client

Source: SUSE built container

This is the same container as the frontend but started in client mode.  This is for convenience to ensure that the UI presents the client events interface immediately without needing to start up an external client.  The client running inside a container will not have access to a number of resource including BPF and the audit netlink socket.  It also cannot accept remote shell commands.  Once the server has been configured it is safe to remove this container.

### Traefik

The `traefik`container is used to implement a TLS reverse proxy capable of obtaining its own certificates via the ACME protocol.

### Kafka cluster

This is optional and for use in environments where the `logscale_upload` plugin can't communicate with the Logscale server. Instead the `kafka_producer` plugin is used to forward events to Kafka, and the `kafka-humio-gateway` is used to pull the events from Kafka and forward them to Logscale.

Certificates for mTLS must be generated before starting Kafka for the first time - see below.


## Configuration

### Example files

Most of the configuration of the containers is done in the containers themselves and need little outside configuration. Still, there are site specific values to be defined. There are example configuration files in the Git repository that will make this easier. Copying the examples and editing them is the simplest way to proceed.. The main Velociraptor configuration file will be automatically generated but will still need to be completed for the site.

- `env.example` -> `.env` -- Defines compose variables

- `config/traefik/traefik.toml.example` -> `config/traefik/traefik.toml`

- `config/velociraptor/server.conf` -- Created by Velociraptor container but needs completion.

- `config/velociraptor/client.conf` -- Created by Velociraptor client container.  No further modification is required.

- `config/velociraptor/client.conf.template` -- Created by Velociraptor container for use with clients.  The server URL will need to be replaced with the real domain name of the deployed server.

- `config/traefik/acme.json` -- Empty file will be filled in by the Traefik container. No further modification is required.

### Internal TLS

Internal TLS has yet to be implemented and will require some changes to the sections below. What follows is what is required to use the Compose environment with _external_ TLS only.

### Sensor Frontend

Locations: `config/velociraptor/server.conf` `.env`

The Velociraptor container will generate its own configuration, including TLS keys/certificates at first startup, but the configuration generated will need to be supplemented with some additional fields before it can be used in this environment.

To generate the initial configuration without starting up the server for the first time, `docker-compose run sensor-frontend /generate-config.sh` will generate the configuration, place it in `config/velociraptor/server.conf`, pull out a template useful for distributing to clients in `config/velociraptor/client.conf.template` and exit.

Until internal TLS is implemented, the GUI must operate in plaintext mode within the container for Traefik to be able to provide a TLS proxy. To enable plain http mode,`use_plain_http: true` must be added to the `GUI` section of `config/velociraptor/server.conf` Since the hostname inside the container will not be used by GUI users,  `public_url: https://public-facing-domain-name` must also be added to work properly.  That hostname must also be added to the `SENSOR_GUI_HOSTNAME` variable defined in`.env`. These must match or authentication will not work properly (as seen by a return to the login screen instead of opening the app.)

Initial authentication is configured to use builtin `Basic` authentication using an internal database. The only user added initially is the `admin` user with a password of `admin`. If authentication using an outside authentication service is required, the following stanza must be added to the `GUI` section of `config/velociraptor/server.conf`:

    GUI:
      authenticator:
        type: oidc
        oidc_issuer: https://id.opensuse.org/openidc/
        avatar: https://en.opensuse.org/images/c/cd/Button-colour.png
        oauth_client_id: $OAUTH_CLIENT_ID
        oauth_client_secret: $OAUTH_CLIENT_SECRET
      initial_users:
      - name: $USER@suse.com

The initial user must be an email address associated with a valid remote account. It will be created as an administrative-level user and can create new user accounts. **Accounts must be created manually.** Once the configuration mechanism is switched from `Basic` to `oidc`, the included `admin` account will be inaccessible.

When configuring the authentication service, the callback URI should be the same as `public_url` above but with `/auth/oidc/callback` appended. For example, `https://sensor-demo.dyn.cloud.suse.de/auth/oidc/callback`

### Traefik

An example `traefik.toml` file is provided as `config/traefik/traefik.toml.example`. Several values must be filled in and the resultant file installed in `config/traefik/traefik.toml`.

- Email Address

- Domain (without the host component)

- The URL for the ACME interface of the CA to be used to issue certificates for this host

If the CA you configure is not otherwise connected to a public chain of trust, the root certificate for the CA must be added to the system's certificate store first. Otherwise, registration will fail with an untrusted certificate error.

### Kafka

If Kafka is to be used, in `.env` set `COMPOSE_PROFILES=kafka` and set `KAFKA_0_FQDN`, `KAFKA_1_FQDN` and `KAFKA_2_FQDN`. These are the fully qualified domain names that `kafka-humio-gateway` will use to communicate with the Kafka cluster using mTLS. These names should resolve to the IP address of the host running docker-compose, by using DNS CNAMEs or other means. Also set `KAFKA_PASSWORD`.

The script to generate the certificates requires the Java `keytool` program which is in the kafka container image

    cd SUSE/docker-compose/
    chown 1001 kafka-certs
    docker run --rm -it -v $PWD/.env:/.env:ro -v $PWD/kafka-certs:/work -w /work bitnami/kafka:3.7.0 /work/generate.sh

This will create the keys and certificates needed for the Kafka cluster to start. Copy the files in `kafka-certs/pem/` to the machine running `kafka-humio-gateway`.

## Startup

Once these steps are completed, a simple `docker-compose up -d` will start up the application.

## Application Configuration

The events collected by Velociraptor are generated using VQL queries. Those queries can be executed manually but more often they are executed automatically using artifacts. Custom artifacts are certainly possible and will be part of any deployment, but the team has assembled a core group of artifacts to meet the requirements laid out by IT Security. This section of the documentation will describe the artifacts needed and what configuration is required. Any of the artifacts can be modified. If a built-in artifact is modified, it is saved as the same name with `Custom.` prefixed to it.

### Server Event Monitoring

The artifacts used for server monitoring include monitoring incoming events and artifacts to forward to another system. The icon to configure Server Events looks like an eye. To configure, click the edit (pencil) button and a selection of Server Event artifacts will be presented.

Select the following artifacts to configure in the next screen.

#### `Logscale.Events.Clients`
This artifact is responsible for listening to _all_ of the incoming events to the Velociraptor server and forwarding events from the selected artifacts to the Logscale ingestion endpoint.
The following parameters must be used:

- `ingestApiBase` -> `https://cloud.community.humio.com/api`

- `ingestToken` -> `appropriate-ingest-token`

- `tagFields` -> `Artifact`

For the other parameters, the defaults can be used.

Then select the required artifacts to forward to Logscale. These parameters may be updated at any time. When a new artifact is added to the system, it will not be forwarded automatically until it is added to the list of artifacts to forward.

A good starting set would be:
- `Generic.Client.Stats`

- `SUSE.Linux.Events.ExecutableFiles`

- `SUSE.Linux.Events.NewFiles`

- `Linux.Events.ProcessExecutions`

- `SUSE.Linux.Events.ProcessStatuses`

- `SUSE.Linux.Events.UserAccount`

- `Server.Monitor.Shell`

- `SUSE.Linux.Events.Crontab/Connections`

- `SUSE.Linux.Events.DNS`

- `SUSE.Linux.Events.ImmutableFile`

- `SUSE.Linux.Events.SSHLogin`

- `SUSE.Linux.Events.TCPConnections`

- `SUSE.Linux.Events.UserGroupMembershipUpdates`

These artifacts may in turn need configuration, which will be described below.

#### `Logscale.Flows.Upload`
This artifact is responsible for listening to all incoming flows to the Velociraptor server and forwarding them to the Logscale ingestion endpoint.

The following parameters must be used:

- `ingestApiBase` -> `https://cloud.community.humio.com/api`

- `ingestToken` -> `appropriate-ingest-token`

- `tagFields` -> `Artifact`

- `ArtifactNameRegex` -> `.`

### `Kafka.Events.Clients`
This artifact is responsible for listening to _all_ of the incoming events to the Velociraptor server and forwarding events from the selected artifacts to the Kafka cluster.
The following parameters must be used:

- `kafkaBrokerAddresses` -> `kafka-0:9092,kafka-1:9092,kafka-2:9092`

- `kafkaTopics` -> `velociraptor-events`

- `tagFields` -> `Artifact`

Then select the required artifacts to forward to Kafka. These parameters may be updated at any time. When a new artifact is added to the system, it will not be forwarded automatically until it is added to the list of artifacts to forward.

A good starting set would be:
- `Generic.Client.Stats`

- `Linux.Events.ExecutableFiles`

- `Linux.Events.NewFiles`

- `Linux.Events.ProcessExecutions`

- `Linux.Events.ProcessStatuses`

- `Linux.Events.UserAccount`

- `Server.Monitor.Shell`

- `SUSE.Linux.Events.Crontab/Connections`

- `SUSE.Linux.Events.DNS/Connections`

- `SUSE.Linux.Events.ImmutableFile/Connections`

- `SUSE.Linux.Events.SSHLogin`

- `SUSE.Linux.Events.Tcp/Connections`

- `SUSE.Linux.Events.UserGroupMembershipUpdates`

These artifacts may in turn need configuration, which will be described below.

### `Kafka.Flows.Upload`
This artifact is responsible for listening to all incoming flows to the Velociraptor server and forwarding them to the Kafka cluster.

The following parameters must be used:

- `kafkaBrokerAddresses` -> `kafka-0:9092,kafka-1:9092,kafka-2:9092`

- `kafkaTopics` -> `velociraptor-events`

- `tagFields` -> `Artifact`

- `ArtifactNameRegex` -> `.`


#### `Server.Monitor.Shell`
This artifact is responsible for logging the output of remote shell sessions and is an important component of the audit trail.  There is no configuration required.

#### `System.Hunt.Creation`
This artifact generates an event when a user of the GUI initiates a new hunt.

### Client Event Monitoring

The artifacts used for client monitoring are the primary purpose of this tool. Unfortunately, the UI to configure client events is a little clunky. It requires at least one client already be associated with the server. In order to streamline this, we've added a sensor client to the Compose environment. To configure the client event monitoring, use the pulldown to the right of the client search box at the top left of the screen. Select "Show All" and the client list will appear. Now the "Client Events" option is available on the sidebar and can be selected. Like with the Server Event Monitoring, the pencil icon configures the artifacts.

To begin, select a label group. It is possible to create arbitrary labels and add them to subsets of hosts, but for now we'll just choose "All" and then choose "Select Artifacts" at the bottom of the pane.

Select the required artifacts. The list should match what we've configured in the `Logscale.Events.Clients` artifact parameters above, ignoring anything following the `/` character as that delimits the _data source_ and we don't care about that for the client artifact. Although some of these artifacts have configurable parameters, the defaults generally do not need to be changed. Click through the rest of the buttons in the bar at the bottom until you complete the process by using the "Launch" button. This will push the new configuration to the endpoints and the new policy will take effect.

## Client Deployment

Packages for deployment on a number of SUSE Linux releases are available on the [Open Build Service](https://download.opensuse.org/repositories/security:/sensor/). The `config/client.conf.template` file (with the correct `server_url`) should be installed at `/etc/velociraptor/client.config`.  The packages will otherwise create the correct directories to host the writeback and buffer files.

## Bugs / Caveats

* Internal TLS needs to be implemented
* There may be outstanding artifacts that need to be committed to the repo. Updates will be forthcoming.
* Please report any issues to the [#proj-linux-security-sensor](https://suse.slack.com/archives/C02NJAA1PEC) Slack channel and/or the GitHub [issues](https://github.com/SUSE/linux-security-sensor/issues) page.
