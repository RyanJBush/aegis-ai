import { useEffect, useState } from 'react';

import PageHeader from '../components/PageHeader';
import { fetchAuditLogs, fetchRuleHistory } from '../services/platformApi';
import { AuditLogEntry, RuleChangeEntry } from '../types';

function GovernancePage() {
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [ruleChanges, setRuleChanges] = useState<RuleChangeEntry[]>([]);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [logs, rules] = await Promise.all([fetchAuditLogs(30), fetchRuleHistory(30)]);
        if (!active) return;
        setAuditLogs(logs);
        setRuleChanges(rules);
        setNotice('Loaded audit and rule governance events.');
      } catch {
        if (!active) return;
        setNotice('Governance endpoints unavailable for current role or backend state.');
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, []);

  return (
    <section className="stack">
      <PageHeader title="Governance" subtitle="Audit trail and scanner rule change history." />
      {notice && <p className="notice">{notice}</p>}

      <section className="card">
        <h3>Rule Change History</h3>
        <div className="table-wrapper">
          <table className="vuln-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Rule</th>
                <th>Change</th>
                <th>Actor</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {ruleChanges.map((entry) => (
                <tr key={entry.id}>
                  <td>{entry.id}</td>
                  <td>{entry.rule_key}</td>
                  <td>{entry.change_type}</td>
                  <td>{entry.actor_user_id}</td>
                  <td>{new Date(entry.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card">
        <h3>Audit Log Events</h3>
        <div className="table-wrapper">
          <table className="vuln-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Action</th>
                <th>Entity</th>
                <th>Actor</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((entry) => (
                <tr key={entry.id}>
                  <td>{entry.id}</td>
                  <td>{entry.action}</td>
                  <td>{entry.entity_type}</td>
                  <td>{entry.actor_user_id ?? 'system'}</td>
                  <td>{new Date(entry.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}

export default GovernancePage;
