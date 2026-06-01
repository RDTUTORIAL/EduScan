import PropTypes from 'prop-types';
import { RadialBarChart, RadialBar, PolarAngleAxis } from 'recharts';

const RiskChart = ({ score, label }) => {
  const chartData = [
    { name: 'risk', value: score, fill: '#06b6d4' },
    { name: 'remaining', value: 100 - score, fill: '#1f2937' },
  ];

  return (
    <div className="glass-panel flex flex-col items-center justify-center space-y-3 p-6 text-center">
      <p className="text-xs uppercase tracking-[0.3em] text-slate-400">{label}</p>
      <div className="relative">
        <RadialBarChart
          width={220}
          height={220}
          cx="50%"
          cy="50%"
          innerRadius={80}
          outerRadius={100}
          barSize={14}
          startAngle={90}
          endAngle={-270}
          data={chartData}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
          <RadialBar background={{ fill: 'rgba(15, 23, 42, 0.5)' }} dataKey="value" cornerRadius={10} />
        </RadialBarChart>
        <div className="absolute inset-0 flex flex-col items-center justify-center font-mono text-slate-100">
          <span className="text-4xl font-semibold">{score}</span>
          <span className="text-xs text-slate-500">/100</span>
        </div>
      </div>
      <p className="text-sm text-slate-400">Semakin tinggi nilai, semakin kritikal risikonya.</p>
    </div>
  );
};

RiskChart.propTypes = {
  score: PropTypes.number.isRequired,
  label: PropTypes.string,
};

RiskChart.defaultProps = {
  label: 'Risk Meter',
};

export default RiskChart;
