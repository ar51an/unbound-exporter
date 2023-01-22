## unbound exporter
<div align="justify">

### Summary
🔸 Exports Unbound DNS server statistic as `Prometheus` metrics.  
🔸 `unbound-exporter` is tailored for [unbound-dashboard](https://github.com/ar51an/unbound-dashboard). Dashboard release includes:  
   &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ➟ Prebuilt _unbound-exporter_ `binary` for arm64.  
   &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ➟ `Service` to automatically run exporter at startup.  
🔸 Unbound `setup` is available at [unbound-redis](https://github.com/ar51an/unbound-redis).

#### Prerequisite:
* Go 1.19 or later.

#
### Compile:
* Copy `go.mod`, `go.sum` & `unbound-exporter.go` from this repo to local dir.
* Run below cmds:  
  > Download dependencies:  
  > `go mod tidy`

  > Build:  
  > `go build`

  > Reduce size:  
  > `strip unbound-exporter`

  > `ℹ️` **Note:**  
  > Make sure `.../go/bin` is in the `PATH`.

#
### Usage
* `unbound-exporter -h`

  > ![Usage](https://user-images.githubusercontent.com/11185794/213894845-05f6336e-ba93-475a-bb97-37f23ce768fa.png)
</div>
