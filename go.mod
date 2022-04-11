module www.velocidex.com/golang/velociraptor

require (
	cloud.google.com/go v0.88.0 // indirect
	cloud.google.com/go/pubsub v1.13.0
	cloud.google.com/go/storage v1.16.0
	github.com/Depado/bfchroma v1.2.0
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible
	github.com/Netflix/go-expect v0.0.0-20210722184520-ef0bf57d82b3 // indirect
	github.com/Showmax/go-fqdn v1.0.0
	github.com/Velocidex/ahocorasick v0.0.0-20180712114356-e1c353eeaaee
	github.com/Velocidex/amsi v0.0.0-20200608120838-e5d93b76f119
	github.com/Velocidex/cryptozip v0.0.0-20200812111814-37033c799bd9
	github.com/Velocidex/etw v0.0.0-20210723072214-4d0cffd1ff22
	github.com/Velocidex/go-elasticsearch/v7 v7.3.1-0.20191001125819-fee0ef9cac6b
	github.com/Velocidex/go-magic v0.0.0-20211018155418-c5dc48282f28
	github.com/Velocidex/go-yara v1.1.10-0.20210726130504-d5e402efc424
	github.com/Velocidex/grpc-go-pool v1.2.2-0.20211129003310-ece3b3fe13f4
	github.com/Velocidex/json v0.0.0-20210402154432-68206e1293d0
	github.com/Velocidex/pkcs7 v0.0.0-20210524015001-8d1eee94a157
	github.com/Velocidex/sflags v0.3.1-0.20210402155316-b09f53df5162
	github.com/Velocidex/survey v1.8.7-0.20190926071832-2ff99cc7aa49
	github.com/Velocidex/ttlcache/v2 v2.9.1-0.20211116035050-ddd93fed62f5
	github.com/Velocidex/yaml/v2 v2.2.8
	github.com/Velocidex/zip v0.0.0-20210101070220-e7ecefb7aad7
	github.com/ZachtimusPrime/Go-Splunk-HTTP/splunk/v2 v2.0.1
	github.com/alecthomas/assert v1.0.0
	github.com/alecthomas/chroma v0.7.2
	github.com/alecthomas/participle v0.7.1
	github.com/alexmullins/zip v0.0.0-20180717182244-4affb64b04d0
	github.com/araddon/dateparse v0.0.0-20210429162001-6b43995a97de
	github.com/aws/aws-sdk-go v1.40.6
	github.com/clbanning/mxj v1.8.4
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/creack/pty v1.1.13 // indirect
	github.com/crewjam/saml v0.4.6-0.20210521115923-29c6295245bd
	github.com/davecgh/go-spew v1.1.1
	github.com/dimchansky/utfbom v1.1.1
	github.com/dustin/go-humanize v1.0.0
	github.com/elastic/go-elasticsearch/v7 v7.3.0 // indirect
	github.com/elastic/go-libaudit v0.4.0
	github.com/evanphx/json-patch v4.5.0+incompatible
	github.com/go-ole/go-ole v1.2.6
	github.com/go-sql-driver/mysql v1.5.0
	github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.2
	github.com/google/btree v1.0.1
	github.com/google/rpmpack v0.0.0-20210518075352-dc539ef4f2ea
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.3.0
	github.com/gorilla/csrf v1.6.2
	github.com/gorilla/schema v1.1.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.5.0
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hillu/go-ntdll v0.0.0-20210404124636-a6f426aa8d92
	github.com/hinshun/vt10x v0.0.0-20180809195222-d55458df857c // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jmoiron/sqlx v1.3.4
	github.com/juju/ratelimit v1.0.1
	github.com/kr/pty v1.1.8 // indirect
	github.com/lib/pq v1.2.0
	github.com/magefile/mage v1.11.0
	github.com/mattn/go-colorable v0.1.7 // indirect
	github.com/mattn/go-isatty v0.0.14
	github.com/mattn/go-pointer v0.0.0-20180825124634-49522c3f3791
	github.com/mattn/go-sqlite3 v1.14.10
	github.com/microcosm-cc/bluemonday v1.0.16
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/panicwrap v1.0.0
	github.com/olekukonko/tablewriter v0.0.4
	github.com/oschwald/maxminddb-golang v1.8.0
	github.com/pkg/errors v0.9.1
	github.com/pkg/sftp v1.12.0
	github.com/pquerna/cachecontrol v0.0.0-20200921180117-858c6e7e6b7e // indirect
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/qri-io/starlib v0.5.0
	github.com/rifflock/lfshook v0.0.0-20180920164130-b9218ef580f5
	github.com/robertkrimen/otto v0.0.0-20210614181706-373ff5438452
	github.com/russross/blackfriday/v2 v2.0.1
	github.com/sebdah/goldie v1.0.0
	github.com/sebdah/goldie/v2 v2.5.3
	github.com/sergi/go-diff v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/tink-ab/tempfile v0.0.0-20180226111222-33beb0518f1a
	github.com/vjeantet/grok v1.0.0
	github.com/xor-gate/ar v0.0.0-20170530204233-5c72ae81e2b7 // indirect
	github.com/xor-gate/debpkg v0.0.0-20181217150151-a0c70a3d4213
	go.starlark.net v0.0.0-20210602144842-1cdb82c9e17a
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292
	golang.org/x/mod v0.4.2
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	golang.org/x/oauth2 v0.0.0-20210628180205-a41e5a781914
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9
	golang.org/x/time v0.0.0-20210611083556-38a9dc6acbc6
	google.golang.org/api v0.51.0
	google.golang.org/genproto v0.0.0-20211118181313-81c1377c94b1
	google.golang.org/grpc v1.42.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
	howett.net/plist v0.0.0-20201203080718-1454fab16a06
	www.velocidex.com/golang/evtx v0.2.1-0.20220107094629-ab487d5f06f1
	www.velocidex.com/golang/go-ese v0.1.1-0.20220107095505-c38622559671
	www.velocidex.com/golang/go-ntfs v0.1.2-0.20210828125207-a1d0ee62467c
	www.velocidex.com/golang/go-pe v0.1.1-0.20220107093716-e91743c801de
	www.velocidex.com/golang/go-prefetch v0.0.0-20200722101157-37e4751dd5ca
	www.velocidex.com/golang/oleparse v0.0.0-20211013063943-0334d69593c1
	www.velocidex.com/golang/regparser v0.0.0-20190625082115-b02dc43c2500
	www.velocidex.com/golang/vfilter v0.0.0-20220118013948-e60108136153
)

require (
	github.com/Velocidex/file-rotatelogs v0.0.0-20211221020724-d12e4dae4e11
	github.com/Velocidex/ordereddict v0.0.0-20220107075049-3dbe58412844
	github.com/evanphx/json-patch/v5 v5.6.0
	github.com/shirou/gopsutil/v3 v3.21.11
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	www.velocidex.com/golang/vtypes v0.0.0-20220107071957-49947f744c34
)

require (
	github.com/Shopify/sarama v1.32.0
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/hillu/go-archive-zip-crypto v0.0.0-20200712202847-bd5cf365dd44 // indirect
	github.com/prometheus/common v0.29.0 // indirect
	github.com/prometheus/procfs v0.7.2 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
)

// replace www.velocidex.com/golang/go-pe => /home/mic/projects/go-pe
// replace www.velocidex.com/golang/vfilter => /home/mic/projects/vfilter
// replace www.velocidex.com/golang/go-ntfs => /home/mic/projects/go-ntfs
// replace www.velocidex.com/golang/evtx => /home/mic/projects/evtx
// replace www.velocidex.com/golang/go-ese => /home/mic/projects/go-ese
// replace github.com/Velocidex/ordereddict => /home/mic/projects/ordereddict
// replace github.com/Velocidex/yaml/v2 => /home/mic/projects/yaml

// replace github.com/Velocidex/go-magic => /home/mic/projects/go-magic
// replace github.com/Velocidex/go-yara => /home/mic/projects/go-yara
// replace github.com/Velocidex/json => /home/mic/projects/json
// replace github.com/russross/blackfriday/v2 => /home/mic/projects/blackfriday
// replace www.velocidex.com/golang/vtypes => /home/mic/projects/vtypes
// replace github.com/Velocidex/ttlcache/v2 => /home/mic/projects/ttlcache

// replace github.com/Velocidex/zip => /home/mic/projects/zip
// replace github.com/Velocidex/sflags => /home/mic/projects/sflags
// replace github.com/Velocidex/etw => /home/mic/projects/etw
// replace github.com/Velocidex/grpc-go-pool => /home/mic/projects/grpc-go-pool

replace github.com/russross/blackfriday/v2 => github.com/Velocidex/blackfriday/v2 v2.0.2-0.20200811050547-4f26a09e2b3b
go 1.16

replace github.com/alecthomas/chroma => github.com/Velocidex/chroma v0.6.8-0.20200418131129-82edc291369c
