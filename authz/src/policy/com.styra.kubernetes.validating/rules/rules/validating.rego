package policy["com.styra.kubernetes.validating"].rules.rules

monitor[decision] {
  parameters := {
    "whitelist": {
      "": set(),
      "docker.io": set(),
      "quay.io": set()
    }
  }

  data.library.v1.kubernetes.admission.workload.v1.repository_unsafe_exact[message]
    with data.library.parameters as parameters

  decision := {
    "allowed": false,
    "message": message
  }
}

monitor[decision] {
  parameters := {
    "allowed": {
      "/main",
      "/nfs/backup"
    }
  }

  data.library.v1.kubernetes.admission.workload.v1.deny_host_path_not_in_whitelist[message]
    with data.library.parameters as parameters

  decision := {
    "allowed": false,
    "message": message
  }
}

monitor[decision] {
  parameters := {
    "whitelist": {
      "172.17.0.0/16"
    }
  }

  data.library.v1.kubernetes.admission.network.v1.deny_ingress_ip_block_not_in_whitelist[message]
    with data.library.parameters as parameters

  decision := {
    "allowed": false,
    "message": message
  }
}

monitor[decision] {
  parameters := {
    "whitelist": set()
  }

  data.library.v1.kubernetes.admission.network.v1.deny_ingress_hostname_not_in_whitelist[message]
    with data.library.parameters as parameters

  decision := {
    "allowed": false,
    "message": message
  }
}

monitor[decision] {
  parameters := {
    "whitelist": {
      "10.0.0.0/24"
    }
  }

  data.library.v1.kubernetes.admission.network.v1.deny_egress_ip_block_not_in_whitelist[message]
    with data.library.parameters as parameters

  decision := {
    "allowed": false,
    "message": message
  }
}

enforce[decision] {
  data.library.v1.kubernetes.admission.workload.v1.expect_container_resource_requests[message]
  decision := {
    "allowed": false,
    "message": message
  }
}

enforce[decision] {
  data.library.v1.kubernetes.admission.workload.v1.block_privileged_mode[message]
  decision := {
    "allowed": false,
    "message": message
  }
}

monitor[decision] {
  data.library.v1.kubernetes.admission.workload.v1.block_latest_image_tag[message]
  decision := {
    "allowed": false,
    "message": message
  }
}

monitor[decision] {
  data.library.v1.kubernetes.admission.network.v1.ingress_missing_tls[message]
  decision := {
    "allowed": false,
    "message": message
  }
}

monitor[decision] {
  data.library.v1.kubernetes.admission.network.v1.ingress_hostpath_conflict[message]
  decision := {
    "allowed": false,
    "message": message
  }
}
