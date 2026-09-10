export type Endpoint = {
  ip: string;
  port: number;
  host?: string;
  host_src?: string;
  org?: string;
  org_detail?: string;
  org_src?: string;
  domain?: string;
  owner?: string;
  registrar?: string;
  age_days?: number;
  favicon?: string;
  asn?: number;
  asn_org?: string;
  country?: string;
  trail?: string[];
};

export type Flow = {
  id: string;
  proto: string;
  pid: number;
  comm: string;
  local: Endpoint;
  remote: Endpoint;
  bytes_up: number;
  bytes_down: number;
  state: string;
  self?: boolean;
  pre_existing?: boolean;
  direct_ip?: boolean;
  queries?: string[];
};

export type Proc = {
  pid: number;
  name: string;
  app?: string;
  path?: string;
  bundle_id?: string;
  icon_id?: string;
};

export type Envelope = {
  type: "hello" | "tick";
  t: number;
  host?: { hostname: string; iface: string; version: string };
  flows?: Flow[];
  procs?: Proc[];
  gone?: string[];
  stats?: {
    live_flows: number;
    with_name: number;
    with_org: number;
    unidentified: number;
    direct_ip: number;
  };
};
