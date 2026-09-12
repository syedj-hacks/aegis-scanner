export default function Footer() {
  return (
    <footer className="border-t border-light-line bg-light-alt">
      <div className="mx-auto flex max-w-6xl flex-col gap-2 px-5 py-8 text-[0.82rem] text-dim sm:flex-row sm:justify-between sm:px-8">
        <div>© {new Date().getFullYear()} Aegis Shield — automated vulnerability assessment</div>
        <a
          href="https://github.com/syedj-hacks/aegis-saas"
          target="_blank"
          rel="noreferrer"
          className="transition-colors hover:text-brand"
        >
          github.com/syedj-hacks/aegis-saas
        </a>
      </div>
    </footer>
  );
}
