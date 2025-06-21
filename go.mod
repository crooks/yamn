module github.com/crooks/yamn

go 1.16

require (
	github.com/Masterminds/log-go v1.0.0
	github.com/crooks/jlog v0.0.0-20230403143904-3805b8c4f892
	github.com/crooks/log-go-level v0.0.0-20221021134405-8ea229e5ea34
	github.com/dchest/blake2s v1.0.0
	github.com/golang/snappy v0.0.4 // indirect
	github.com/luksen/maildir v0.0.0-20210101204218-7ed7afdce6bf
	github.com/syndtr/goleveldb v1.0.0
	golang.org/x/crypto v0.14.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/Masterminds/log-go v0.4.0 => github.com/crooks/log-go v0.4.1

replace github.com/coreos/go-systemd => github.com/coreos/go-systemd/v22 v22.3.2
