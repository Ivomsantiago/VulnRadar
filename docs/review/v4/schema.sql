CREATE INDEX ix_activity_kind ON activity (kind);
CREATE INDEX ix_activity_subject ON activity (subject);
CREATE INDEX ix_advisories_source ON advisories (source);
CREATE INDEX ix_advisories_vulnerability_id ON advisories (vulnerability_id);
CREATE INDEX ix_affected_packages_advisory_id ON affected_packages (advisory_id);
CREATE INDEX ix_affected_packages_ecosystem ON affected_packages (ecosystem);
CREATE INDEX ix_affected_packages_package ON affected_packages (package);
CREATE INDEX ix_affected_products_advisory_id ON affected_products (advisory_id);
CREATE INDEX ix_affected_products_product ON affected_products (product);
CREATE INDEX ix_affected_products_vendor ON affected_products (vendor);
CREATE INDEX ix_aliases_vulnerability_id ON aliases (vulnerability_id);
CREATE INDEX ix_finding_observations_finding_id ON finding_observations (finding_id);
CREATE INDEX ix_finding_observations_scan_id ON finding_observations (scan_id);
CREATE INDEX ix_finding_states_finding_id ON finding_states (finding_id);
CREATE INDEX ix_finding_states_occurred_at ON finding_states (occurred_at);
CREATE INDEX ix_finding_states_project_id ON finding_states (project_id);
CREATE INDEX ix_findings_fingerprint ON findings (fingerprint);
CREATE INDEX ix_findings_kind ON findings (kind);
CREATE INDEX ix_findings_project_id ON findings (project_id);
CREATE INDEX ix_findings_scan_id ON findings (scan_id);
CREATE INDEX ix_findings_severity ON findings (severity);
CREATE INDEX ix_findings_status ON findings (status);
CREATE INDEX ix_findings_vulnerability_id ON findings (vulnerability_id);
CREATE INDEX ix_inventory_components_ecosystem ON inventory_components (ecosystem);
CREATE INDEX ix_inventory_components_package ON inventory_components (package);
CREATE INDEX ix_inventory_components_project_id ON inventory_components (project_id);
CREATE INDEX ix_inventory_components_scan_id ON inventory_components (scan_id);
CREATE INDEX ix_notification_deliveries_status ON notification_deliveries (status);
CREATE INDEX ix_scans_project_id ON scans (project_id);
CREATE INDEX ix_scans_status ON scans (status);
CREATE INDEX ix_sync_runs_source ON sync_runs (source);
CREATE INDEX ix_vulnerabilities_kev ON vulnerabilities (kev);
CREATE INDEX ix_vulnerabilities_published ON vulnerabilities (published);
CREATE INDEX ix_vulnerabilities_severity ON vulnerabilities (severity);
CREATE INDEX ix_vulnerabilities_triage ON vulnerabilities (triage);
CREATE INDEX ix_watchlist_package ON watchlist (package);
CREATE TABLE activity (
	id INTEGER NOT NULL, 
	kind VARCHAR(40) NOT NULL, 
	subject VARCHAR(240) NOT NULL, 
	data JSON NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE advisories (
	id VARCHAR(240) NOT NULL, 
	vulnerability_id VARCHAR(160) NOT NULL, 
	source VARCHAR(30) NOT NULL, 
	payload JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities (id)
);
CREATE TABLE affected_packages (
	id INTEGER NOT NULL, 
	advisory_id VARCHAR(240) NOT NULL, 
	ecosystem VARCHAR(80) NOT NULL, 
	package VARCHAR(300) NOT NULL, 
	constraints JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(advisory_id) REFERENCES advisories (id)
);
CREATE TABLE affected_products (
	id INTEGER NOT NULL, 
	advisory_id VARCHAR(240) NOT NULL, 
	vendor VARCHAR(200) NOT NULL, 
	product VARCHAR(200) NOT NULL, 
	constraints JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(advisory_id) REFERENCES advisories (id)
);
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
CREATE TABLE aliases (
	id VARCHAR(160) NOT NULL, 
	vulnerability_id VARCHAR(160) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities (id)
);
CREATE TABLE finding_observations (
	id INTEGER NOT NULL, 
	scan_id INTEGER NOT NULL, 
	finding_id INTEGER NOT NULL, 
	evidence JSON NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_scan_finding UNIQUE (scan_id, finding_id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id)
);
CREATE TABLE finding_states (
	id INTEGER NOT NULL, 
	finding_id INTEGER NOT NULL, 
	project_id INTEGER NOT NULL, 
	occurred_at DATETIME NOT NULL, 
	action VARCHAR(30) NOT NULL, 
	data JSON NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(finding_id) REFERENCES findings (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id)
);
CREATE TABLE findings (
	id INTEGER NOT NULL, 
	project_id INTEGER NOT NULL, 
	scan_id INTEGER NOT NULL, 
	fingerprint VARCHAR(64) NOT NULL, 
	kind VARCHAR(10) NOT NULL, 
	vulnerability_id VARCHAR(160), 
	package VARCHAR(300), 
	ecosystem VARCHAR(80), 
	version VARCHAR(150), 
	file TEXT NOT NULL, 
	line INTEGER, 
	rule_id VARCHAR(300), 
	severity VARCHAR(20) NOT NULL, 
	status VARCHAR(50) NOT NULL, 
	evidence JSON NOT NULL, 
	fixed_versions JSON NOT NULL, 
	first_seen DATETIME NOT NULL, 
	last_seen DATETIME NOT NULL, owner VARCHAR(150), due_at DATETIME, risk_expires_at DATETIME, remediation_plan TEXT, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_finding_identity UNIQUE (project_id, kind, fingerprint), 
	FOREIGN KEY(project_id) REFERENCES projects (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id), 
	FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities (id)
);
CREATE TABLE inventory_components (
	id INTEGER NOT NULL, 
	project_id INTEGER NOT NULL, 
	scan_id INTEGER NOT NULL, 
	ecosystem VARCHAR(80) NOT NULL, 
	package VARCHAR(300) NOT NULL, 
	version VARCHAR(150) NOT NULL, 
	file TEXT NOT NULL, 
	direct BOOLEAN, 
	query_status VARCHAR(30) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id), 
	FOREIGN KEY(scan_id) REFERENCES scans (id)
);
CREATE TABLE notification_deliveries (
	id INTEGER NOT NULL, 
	activity_id INTEGER NOT NULL, 
	channel VARCHAR(20) NOT NULL, 
	status VARCHAR(30) NOT NULL, 
	attempts INTEGER NOT NULL, 
	last_attempt DATETIME, 
	next_attempt DATETIME, 
	error VARCHAR(200), 
	PRIMARY KEY (id), 
	UNIQUE (activity_id), 
	FOREIGN KEY(activity_id) REFERENCES activity (id)
);
CREATE TABLE platform_settings (
	"key" VARCHAR(80) NOT NULL, 
	value JSON NOT NULL, 
	PRIMARY KEY ("key")
);
CREATE TABLE product_watches (
	id INTEGER NOT NULL, 
	vendor VARCHAR(200) NOT NULL, 
	product VARCHAR(200) NOT NULL, 
	version VARCHAR(100) NOT NULL, 
	alerts_enabled BOOLEAN DEFAULT 1 NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE projects (
	id INTEGER NOT NULL, 
	name VARCHAR NOT NULL, 
	path VARCHAR NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (path)
);
CREATE TABLE scans (
	id INTEGER NOT NULL, 
	project_id INTEGER NOT NULL, 
	kind VARCHAR NOT NULL, 
	status VARCHAR NOT NULL, 
	result JSON NOT NULL, 
	created_at DATETIME NOT NULL, 
	completed_at DATETIME, stage VARCHAR(40) DEFAULT 'queued' NOT NULL, "indexed" BOOLEAN DEFAULT 0 NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(project_id) REFERENCES projects (id)
);
CREATE TABLE sources (
	id VARCHAR(30) NOT NULL, 
	status VARCHAR NOT NULL, 
	checkpoint VARCHAR, 
	last_run VARCHAR, 
	error TEXT, 
	count INTEGER NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE sync_runs (
	id INTEGER NOT NULL, 
	source VARCHAR(30) NOT NULL, 
	status VARCHAR(30) NOT NULL, 
	started_at DATETIME NOT NULL, 
	completed_at DATETIME, 
	duration_ms INTEGER, 
	new_count INTEGER NOT NULL, 
	updated_count INTEGER NOT NULL, 
	processed_count INTEGER NOT NULL, 
	pages INTEGER NOT NULL, 
	error TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE vulnerabilities (
	id VARCHAR(160) NOT NULL, 
	title TEXT NOT NULL, 
	description TEXT NOT NULL, 
	severity VARCHAR(20) NOT NULL, 
	cvss FLOAT, 
	epss FLOAT, 
	kev BOOLEAN NOT NULL, 
	published VARCHAR(60), 
	modified VARCHAR, 
	triage VARCHAR(50) NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE watchlist (
	id INTEGER NOT NULL, 
	ecosystem VARCHAR NOT NULL, 
	package VARCHAR NOT NULL, 
	version VARCHAR, min_severity VARCHAR(20) DEFAULT 'LOW' NOT NULL, alerts_enabled BOOLEAN DEFAULT 1 NOT NULL, 
	PRIMARY KEY (id)
);