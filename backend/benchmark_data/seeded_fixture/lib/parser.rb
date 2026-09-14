# Seeded benchmark fixture (INTENTIONALLY VULNERABLE — not shipped).
module Formulary
  # GT: SEED-RB-EVAL-1 — Ruby code injection via instance_eval on untrusted source.
  def self.load_formula(src)
    instance_eval(src)
  end

  # KNOWN-SAFE: argv exec, no shell — must not be surfaced as command injection.
  def self.list_files(dir)
    system("ls", "-la", dir)
  end
end
