import { motion } from 'framer-motion';
import { Github, Instagram, Linkedin, ArrowUpRight } from 'lucide-react';

const SOCIAL_LINKS = [
  {
    id: 'github',
    label: 'GitHub',
    handle: 'github.com/RDTUTORIAL',
    href: 'https://github.com/RDTUTORIAL',
    icon: Github,
  },
  {
    id: 'instagram',
    label: 'Instagram',
    handle: '@kd.dnswra',
    href: 'https://instagram.com/kd.dnswra',
    icon: Instagram,
  }
];

const Contact = () => (
  <motion.section className="flex flex-col gap-6" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
    <header className="rounded-2xl border border-white/5 bg-gradient-to-r from-slate-900/60 to-slate-900/30 p-6">
      <h2 className="text-3xl font-semibold text-white">Justine</h2>
    </header>

    <div className="glass-panel space-y-4 p-6">
      {SOCIAL_LINKS.map(({ id, label, handle, href, icon: Icon }) => (
        <a
          key={id}
          href={href}
          target="_blank"
          rel="noreferrer"
          className="flex items-center justify-between rounded-2xl border border-white/5 bg-white/5 p-4 text-white transition hover:border-cyan-400/50"
        >
          <div className="flex items-center gap-4">
            <span className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-white/10 bg-slate-900/60 text-cyan-200">
              <Icon className="h-5 w-5" />
            </span>
            <div>
              <p className="text-sm font-semibold">{label}</p>
              <p className="text-xs text-slate-400">{handle}</p>
            </div>
          </div>
          <ArrowUpRight className="h-5 w-5 text-slate-400" />
        </a>
      ))}
    </div>
  </motion.section>
);

export default Contact;
