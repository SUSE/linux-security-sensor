//go:build linux

package linux

import (
	"context"
	"fmt"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/Velocidex/ordereddict"
	rpmdb "github.com/djoreilly/go-rpmdb/pkg"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/vql"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

var (
	defaultPaths = []string{"/var/lib/rpm"}
	dbFiles      = []string{"Packages.db", "Packages", "rpmdb.sqlite"}
	defaultTags  = []string{
		"Name", "Summary", "Version", "Release", "InstallTime",
		"PublicKey", "PublicKeyName",
	}
)

const (
	RPMTAG_FAKE_PUBLICKEY = iota + 100000
	RPMTAG_FAKE_PUBLICKEYNAME
)

type _RPMPluginArgs struct {
	Paths []string `vfilter:"optional,field=paths,doc=Paths to search for rpm database (default: /var/lib/rpm)"`
	Tags  []string `vfilter:"optional,field=tags,doc=List of tags to retreive for each package (default: Name,Summary,Version,Release,InstallTime,PublicKey,PublicKeyName)"`
}

type RPMPlugin struct{}

func publishPackages(ctx context.Context, scope vfilter.Scope, tags []string, paths []string,
		     output_chan chan vfilter.Row) error {
	var db *rpmdb.RpmDB
	var errs []error
	var err error

	for _, path := range paths {
		for _, file := range dbFiles {
			dbpath := path + "/" + file
			db, err = rpmdb.Open(dbpath)
			if err == nil {
				break
			}
			errs = append(errs, err)
		}
		if db != nil {
			break
		}
	}

	if db == nil {
		return fmt.Errorf("failed to open rpm database: %v", errs)
	}

	needPGP := false
	needPubKey := false
	needPubKeyName := false
	needSummary := false
	needDescription := false
	tagQuery := []string{}
	tagIDs := []int32{}
	for _, tag := range tags {
		switch strings.ToUpper(tag) {
		case "SUMMARY":
			needSummary = true
			tagQuery = append(tagQuery, tag)
			tagIDs = append(tagIDs, rpmdb.RPMTAG_SUMMARY)
		case "DESCRIPTION":
			needDescription = true
			tagQuery = append(tagQuery, tag)
			tagIDs = append(tagIDs, rpmdb.RPMTAG_DESCRIPTION)
		case "PUBLICKEYNAME":
			needPubKeyName = true
			tagIDs = append(tagIDs, RPMTAG_FAKE_PUBLICKEYNAME)
		case "PUBLICKEY":
			needPubKey = true
			tagIDs = append(tagIDs, RPMTAG_FAKE_PUBLICKEY)
		case "PGP":
			needPGP = true
			tagQuery = append(tagQuery, tag)
			tagIDs = append(tagIDs, rpmdb.RPMTAG_PGP)
		default:
			tagQuery = append(tagQuery, tag)
			tagid, err := rpmdb.TagID(strings.ToUpper(tag))
			if err != nil {
				return err
			}
			tagIDs = append(tagIDs, tagid)

		}
	}

	// PUBKEY and PUBKEYNAME imply PGP
	if !needPGP && (needPubKey || needPubKeyName) {
		tagQuery = append(tagQuery, "pgp")
	}

	if !needSummary && (needPGP || needPubKey || needPubKeyName) {
		tagQuery = append(tagQuery, "summary")
	}

	// PUBKEYNAME also implies DESCRIPTION since that's where
	// the armored key is stored
	if !needDescription && (!needPubKeyName || needPubKeyName) {
		tagQuery = append(tagQuery, "description")
	}

	pkgList, err := db.ListPackagesAsPackageInfoMap(tagQuery)
	if err != nil {
		return err
	}

	// Cache the public keys, if needed, so we can use them below
	pubKeyMap := map[string]string{}
	if needPGP || needPubKey || needPubKeyName {
		for _, pkg := range pkgList {
			name := pkg.Name()
			if name == "gpg-pubkey" {
				key, err := crypto.NewKeyFromArmored(pkg.Description())
				if err != nil {
					scope.Log("error while reading key for \"%s\": %v",
						pkg.Summary(), err)
					continue
				}
				keyid := key.GetEntity().PrimaryKey.KeyIdString()
				pubKeyMap[keyid] = pkg.Summary()
			}
		}
	}

	for _, pkg := range pkgList {
		name := pkg.Name()
		if name != "gpg-pubkey" {
			var pgp *rpmdb.PGPInfo

			row := ordereddict.NewDict()

			if needPGP || needPubKey || needPubKeyName {
				pgp, _ = pkg.PGP()
			}

			for i, tagid := range tagIDs {
				switch tagid {
				case rpmdb.RPMTAG_PGP:
					if pgp != nil {
						row.Set(tags[i], pgp.String())
					} else {
						row.Set(tags[i], "")
					}
				case RPMTAG_FAKE_PUBLICKEY:
					if pgp != nil {
						pubkey := fmt.Sprintf("%X", pgp.KeyID)
						row.Set(tags[i], pubkey)
					} else {
						row.Set(tags[i], "")
					}
				case RPMTAG_FAKE_PUBLICKEYNAME:
					if pgp != nil {
						pubkey := fmt.Sprintf("%X", pgp.KeyID)
						pubkeyname, ok := pubKeyMap[pubkey]
						if !ok {
							pubkeyname = fmt.Sprintf("unknown:%X", pgp.KeyID)
						}
						row.Set(tags[i], pubkeyname)
					} else {
						row.Set(tags[i], "")
					}
				default:
					row.Set(tags[i], pkg.Tags[tagid].Value)
				}
			}

			output_chan <- row
		}
	}

	return nil
}

func (self RPMPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     "rpm",
		Doc:      "Query the installed packages on a Linux system using RPMs",
		ArgType:  type_map.AddType(scope, &_RPMPluginArgs{}),
		Metadata: vql.VQLMetadata().Permissions(acls.MACHINE_STATE).Build(),
	}
}

func (self RPMPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)

		scope.Log("rpm: starting up")

		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("rpm: %s", err)
			return
		}

		arg := _RPMPluginArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, &arg)

		paths := arg.Paths
		if len(paths) == 0 {
			paths = defaultPaths
		}

		tags := defaultTags
		if len(arg.Tags) > 0 {
			tags = arg.Tags
		}

		err = publishPackages(ctx, scope, tags, paths, output_chan)
		if err != nil {
			scope.Log("rpm: %v", err)
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&RPMPlugin{})
}
