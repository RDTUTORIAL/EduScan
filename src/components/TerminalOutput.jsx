import PropTypes from 'prop-types';
import { motion, AnimatePresence } from 'framer-motion';
import { useEffect, useRef } from 'react';

const lineVariants = {
  initial: { opacity: 0, y: 6 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -6 },
};

const TerminalOutput = ({ logs, status }) => {
  const terminalRef = useRef(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="glass-panel flex flex-col gap-4 p-5">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold text-slate-300">Terminal</p>
        <span
          className={`rounded-full px-3 py-1 text-xs font-semibold ${
            status === 'Scanning...'
              ? 'bg-amber-400/20 text-amber-200'
              : status === 'Done'
              ? 'bg-emerald-400/20 text-emerald-200'
              : 'bg-slate-700/70 text-slate-300'
          }`}
        >
          {status}
        </span>
      </div>
      <div
        ref={terminalRef}
        className="min-h-[220px] max-h-[300px] overflow-y-auto rounded-xl border border-slate-800/80 bg-black/70 p-4 font-mono text-xs text-emerald-200 shadow-inner shadow-cyan-500/5"
      >
        <AnimatePresence initial={false}>
          {logs.length === 0 && (
            <motion.p
              className="text-slate-500"
              initial="initial"
              animate="animate"
              exit="exit"
              variants={lineVariants}
            >
              Belum ada log. Mulai scan untuk melihat output real-time.
            </motion.p>
          )}
          {logs.map((log) => (
            <motion.div
              key={log.id}
              className={`flex items-start gap-3 py-1 ${log.variant === 'error' ? 'text-rose-300' : ''}`}
              initial="initial"
              animate="animate"
              exit="exit"
              variants={lineVariants}
            >
              <span className="text-cyan-400">{'>'}</span>
              <p className="whitespace-pre-wrap">{log.message}</p>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
};

TerminalOutput.propTypes = {
  logs: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      message: PropTypes.string.isRequired,
      variant: PropTypes.oneOf(['default', 'error']),
    }),
  ),
  status: PropTypes.string,
};

TerminalOutput.defaultProps = {
  logs: [],
  status: 'Ready',
};

export default TerminalOutput;
