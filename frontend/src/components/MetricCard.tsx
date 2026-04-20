type MetricCardProps = {
  label: string;
  value: string | number;
  detail: string;
};

function MetricCard({ label, value, detail }: MetricCardProps) {
  return (
    <article className="metric-card">
      <p>{label}</p>
      <h3>{value}</h3>
      <small>{detail}</small>
    </article>
  );
}

export default MetricCard;
