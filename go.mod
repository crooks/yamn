module github.com/crooks/yamn

go 1.16

require (
	github.com/Masterminds/log-go v0.4.0
	github.com/crooks/jlog v0.0.0-20211114164956-865f9c8ec45f
	github.com/dchest/blake2s v1.0.0
	github.com/golang/snappy v0.0.4 // indirect
	github.com/luksen/maildir v0.0.0-20210101204218-7ed7afdce6bf
	github.com/syndtr/goleveldb v1.0.0
	golang.org/x/crypto v0.0.0-20220128200615-198e4374d7ed
	golang.org/x/sys v0.1.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

replace github.com/Masterminds/log-go v0.4.0 => github.com/crooks/log-go v0.4.1

replace github.com/coreos/go-systemd => github.com/coreos/go-systemd/v22 v22.3.2
