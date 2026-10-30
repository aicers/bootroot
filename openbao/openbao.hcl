storage "raft" {
  path    = "/openbao/raft"
  node_id = "openbao"
}

cluster_addr = "https://127.0.0.1:8201"
api_addr     = "http://127.0.0.1:8200"

listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "127.0.0.1:8201"
  tls_disable = 1
  telemetry {
    disallow_metrics = true
  }
}

listener "tcp" {
  address = "0.0.0.0:9101"
  cluster_address = "127.0.0.1:9102"
  tls_disable = 1
  telemetry {
    metrics_only = true
    unauthenticated_metrics_access = true
  }
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}

audit {
  type = "file"
  path = "stdout"
  options {
    file_path = "stdout"
  }
}

ui = true
