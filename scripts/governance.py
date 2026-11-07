"""Repository documentation, new-commit, and PR contribution checks (stdlib only)."""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import shutil
import unittest
from urllib.parse import unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]
IDENTITY = ('NeerajCodz', 'neerajcodz@gmail.com')
REPOSITORY = 'Astraive/praxor'
GOVERNANCE_ISSUE_URL = 'https://github.com/Astraive/praxor/issues/104'
GOVERNANCE_TICKET = 'PRX-GOV-001'
GOVERNANCE_SPEC_URL = 'https://github.com/Astraive/praxor/blob/main/docs/specs/2026-11-06-contribution-foundation.md'
HEADER = re.compile(r'^(feat|fix|docs|test|build|chore|perf|refactor|ci|revert)\([a-z0-9][a-z0-9._/-]*\)!?: \S.*$')
TICKET = re.compile(r'\[[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d+\]')
ISSUE = re.compile(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[1-9]\d*\b')

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True, encoding='utf-8').strip()

def message_errors(message, author=None, committer=None):
    lines=message.lstrip('\ufeff').splitlines()
    subject=lines[0] if lines else ''
    errors=[]
    if not HEADER.fullmatch(subject) or len(subject)>120:
        errors.append('Use type(scope): message, at most 120 characters in the subject.')
    if re.search(r'^\s*co-authored-by\s*:',message,re.I|re.M):
        errors.append('Co-author trailers are not allowed for this project work.')
    for label,ident in [('author',author),('committer',committer)]:
        if ident is not None and tuple(ident)!=IDENTITY:
            errors.append('New '+label+' must be NeerajCodz <neerajcodz@gmail.com>.')
    return errors

def identity(kind):
    value=git('var','GIT_'+kind+'_IDENT')
    match=re.fullmatch(r'(.*) <([^<>]+)> \d+ [+-]\d{4}',value)
    if not match:raise ValueError('Cannot read Git '+kind.lower()+' identity')
    return match[1],match[2]

def pr_errors(title,body):
    errors=message_errors(title)
    if not TICKET.search(title):errors.append('PR title needs the canonical [TICKET-ID].')
    if not ISSUE.search(body):errors.append('PR body needs an actual GitHub issue URL.')
    for heading in ['Summary','Acceptance criteria','Verification','Dependencies','Compatibility and risks']:
        if not re.search(r'^## '+re.escape(heading)+r'\s*$',body,re.M):errors.append('Missing PR section: '+heading)
    spec=re.search(r'(?im)^spec(?:ification)?\s*:\s*(\S[^\r\n]*)',body)
    if not spec:
        errors.append('PR body needs Spec: <path/URL>, or Spec: not applicable — <reason>.')
    else:
        value=spec[1].strip().strip('`')
        if value.lower().startswith('not applicable'):
            if not re.fullmatch(r'not applicable\s*(?:—|:|-)\s*.{10,}',value,re.I):errors.append('Explain why a specification is not applicable.')
        elif value.startswith('https://'):
            if not urlsplit(value).netloc or any(c.isspace() for c in value):errors.append('Spec URL is malformed.')
        else:
            target=(ROOT/unquote(urlsplit(value).path)).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():errors.append('Spec path does not name a file in this repository.')
    return errors

def markdown_targets(content):
    lines=[];fence=None
    for line in content.splitlines():
        mark=re.match(r'^\s{0,3}(`{3,}|~{3,})',line)
        if mark:
            token=mark[1]
            if fence is None:fence=token
            elif token[0]==fence[0] and len(token)>=len(fence):fence=None
            continue
        if fence is None:lines.append(line)
    content='\n'.join(lines)
    content=re.sub(r'(`+)[^`]*?\1','',content)
    definitions={}
    def first_target(text):
        text=text.strip()
        if text.startswith('<'):return text[1:].split('>',1)[0]
        # Read the destination only; optional quoted link titles are not paths.
        pos=0;depth=0;out=[]
        while pos<len(text):
            c=text[pos]
            if c=='\\' and pos+1<len(text):out.append(text[pos+1]);pos+=2;continue
            if c=='(' :depth+=1
            elif c==')':
                if depth==0:break
                depth-=1
            if c.isspace() and depth==0:break
            out.append(c);pos+=1
        return ''.join(out)
    for match in re.finditer(r'^\s{0,3}\[([^\]\n]+)\]:\s*(.+)$',content,re.M):
        definitions[match[1].strip().casefold()]=first_target(match[2])
    for match in re.finditer(r'(?<!!)\[[^\]\n]+\]\(',content):
        yield first_target(content[match.end():])
    for match in re.finditer(r'(?<!!)\[([^\]\n]+)\]\[([^\]\n]*)\]',content):
        key=(match[2] or match[1]).strip().casefold()
        yield definitions.get(key,'MISSING-REFERENCE:'+key)

def documentation_errors(root):
    errors=[]
    required=['README.md','GIT.md','AGENTS.md','docs/architecture.md','docs/development.md','docs/status-roadmap.md','docs/specs/README.md','docs/specs/TEMPLATE.md']
    for relative in required:
        if not (root/relative).is_file():errors.append('Missing required documentation: '+relative)
    agents=root/'AGENTS.md'
    if agents.is_file() and len(agents.read_text(encoding='utf-8-sig').splitlines())>80:
        errors.append('Keep AGENTS.md at most 80 lines; detailed policy belongs in GIT.md/docs.')
    # Check Markdown target files locally, without network or secret-bearing URLs.
    for path in sorted(root.rglob('*.md')):
        if any(p in {'.git','target','node_modules','.worktrees','.venv','vendor'} for p in path.relative_to(root).parts):continue
        for target in markdown_targets(path.read_text(encoding='utf-8-sig')):
            if target.startswith('MISSING-REFERENCE:'):
                errors.append(str(path.relative_to(root))+': '+target);continue
            parsed=urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:continue
            relative=unquote(parsed.path)
            if not (path.parent/relative).exists():errors.append(str(path.relative_to(root))+': broken local link '+target)
    return errors

def check(base=None,head='HEAD',event=None):
    errors=documentation_errors(ROOT)
    if base:
        for revision in [base,head]:
            if not re.fullmatch(r'[0-9a-fA-F]{40,64}|HEAD',revision):raise ValueError('Expected a full Git revision')
        commits=git('rev-list','--reverse',base+'..'+head).splitlines()
        for sha in commits:
            values=git('show','-s','--format=%an%n%ae%n%cn%n%ce%n%B',sha).splitlines()
            errors.extend(sha[:12]+': '+e for e in message_errors('\n'.join(values[4:]),values[:2],values[2:4]))
    if event:
        payload=json.loads(pathlib.Path(event).read_text(encoding='utf-8'))
        pr=payload.get('pull_request')
        if pr:errors.extend(pr_errors(pr['title'],pr.get('body') or ''))
    return errors

class GovernanceTests(unittest.TestCase):
    def test_actual_hook_in_checkout_with_spaces(self):
        hook=ROOT/'.githooks/commit-msg'
        if not hook.is_file():self.skipTest('Hook is installed by the contribution foundation.')
        shell=shutil.which('sh')
        if not shell and os.name=='nt':
            candidate=pathlib.Path(shutil.which('git')).parents[1]/'bin/sh.exe'
            if candidate.is_file():shell=str(candidate)
        if not shell:self.fail('POSIX sh/Git Bash is required for the hook fixture.')
        with tempfile.TemporaryDirectory(prefix='governance hook fixture ') as folder:
            target=pathlib.Path(folder)
            subprocess.run(['git','init','-q',str(target)],check=True,capture_output=True)
            (target/'scripts').mkdir();(target/'.githooks').mkdir()
            shutil.copyfile(__file__,target/'scripts/governance.py');shutil.copyfile(hook,target/'.githooks/commit-msg')
            message=target/'commit message.txt'
            env=dict(os.environ,GIT_AUTHOR_NAME=IDENTITY[0],GIT_AUTHOR_EMAIL=IDENTITY[1],GIT_COMMITTER_NAME=IDENTITY[0],GIT_COMMITTER_EMAIL=IDENTITY[1])
            cases=[('docs(governance): verify hook\r\n',0,False),('update docs\n',1,False),('docs(git): rules\n\nCo-authored-by: Somebody <somebody@example.invalid>\n',1,False),('docs(git): rules\n',1,True)]
            for text,wanted,wrong_committer in cases:
                message.write_bytes(text.encode())
                case_env=dict(env)
                if wrong_committer:case_env['GIT_COMMITTER_NAME']='GitHub'
                result=subprocess.run([shell,str(target/'.githooks/commit-msg'),str(message)],cwd=target,env=case_env,capture_output=True,text=True)
                with self.subTest(text=text,wrong_committer=wrong_committer):self.assertEqual(result.returncode,wanted,result.stderr)
    def test_normal_conventional_and_merge_messages(self):
        for message in [f'docs(governance): document contribution rules\n\nRefs: {GOVERNANCE_ISSUE_URL}\n','chore(merge): integrate verified documentation','feat(query)!: version typed parameters\r\n\r\nBREAKING CHANGE: explicit types\r\n']:
            with self.subTest(message=message):self.assertEqual(message_errors(message,IDENTITY,IDENTITY),[])
    def test_malformed_and_coauthor_messages(self):
        for message in ['update docs','feat: missing scope','fix(query): ','docs(git): rules\n\nCo-authored-by: Someone <someone@example.invalid>','docs(git): rules\r\n\r\nco-AUTHORED-by: Someone <someone@example.invalid>']:
            with self.subTest(message=message):self.assertTrue(message_errors(message,IDENTITY,IDENTITY))
    def test_identity_is_checked_for_author_and_committer(self):
        self.assertTrue(message_errors('docs(git): rules',('Codex','codex@example.invalid'),IDENTITY))
        self.assertTrue(message_errors('docs(git): rules',IDENTITY,('GitHub','noreply@github.com')))
    def test_pr_requires_issue_spec_and_evidence_sections(self):
        body=f'Refs: {GOVERNANCE_ISSUE_URL}\nSpec: {GOVERNANCE_SPEC_URL}\n'+ '\n'.join('## '+h+'\nConcrete evidence.' for h in ['Summary','Acceptance criteria','Verification','Dependencies','Compatibility and risks'])
        self.assertEqual(pr_errors(f'docs(governance): define workflow [{GOVERNANCE_TICKET}]',body),[])
        self.assertTrue(pr_errors('docs(governance): define workflow',body))
        self.assertTrue(pr_errors(f'docs(governance): define workflow [{GOVERNANCE_TICKET}]',body.replace(GOVERNANCE_ISSUE_URL,GOVERNANCE_TICKET)))
        self.assertTrue(pr_errors(f'docs(governance): define workflow [{GOVERNANCE_TICKET}]',body.replace('Spec:','Missing:')))
        self.assertTrue(pr_errors(f'docs(governance): define workflow [{GOVERNANCE_TICKET}]',body.replace('Spec: '+GOVERNANCE_SPEC_URL,'Spec: docs/specs/DOES-NOT-EXIST.md')))
        self.assertTrue(pr_errors(f'docs(governance): define workflow [{GOVERNANCE_TICKET}]',body.replace('Spec: '+GOVERNANCE_SPEC_URL,'Spec: not applicable')))
    def test_markdown_destinations(self):
        self.assertEqual(list(markdown_targets('[A](docs/a(b).md)\n[B](docs/b.md \'title\')\n`[ignored](absent.md)`\n~~~\n[ignored](absent.md)\n~~~\n[C][ref]\n[ref]: docs/c.md "title"')),['docs/a(b).md','docs/b.md','docs/c.md'])
        self.assertEqual(list(markdown_targets('[Unknown][missing]')),['MISSING-REFERENCE:missing'])
    def test_local_links_and_crisp_agents(self):
        with tempfile.TemporaryDirectory(prefix='governance fixture ') as folder:
            root=pathlib.Path(folder)
            for relative in ['README.md','GIT.md','AGENTS.md','docs/architecture.md','docs/development.md','docs/status-roadmap.md','docs/specs/README.md','docs/specs/TEMPLATE.md']:
                p=root/relative;p.parent.mkdir(exist_ok=True,parents=True);p.write_text('# Documentation\n',encoding='utf-8')
            (root/'README.md').write_text('[Architecture](docs/architecture.md)\r\n',encoding='utf-8')
            self.assertEqual(documentation_errors(root),[])
            (root/'README.md').write_text('[Missing](docs/missing.md)\n',encoding='utf-8')
            self.assertTrue(documentation_errors(root))
            (root/'AGENTS.md').write_text('line\n'*81,encoding='utf-8')
            self.assertTrue(any('80 lines' in e for e in documentation_errors(root)))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('check');p.add_argument('--base');p.add_argument('--head',default='HEAD');p.add_argument('--event')
    p=sub.add_parser('commit-msg');p.add_argument('file')
    sub.add_parser('self-test')
    args=parser.parse_args()
    if args.command=='self-test':
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(GovernanceTests))
        return 0 if result.wasSuccessful() else 1
    if args.command=='commit-msg':
        text=pathlib.Path(args.file).read_text(encoding='utf-8-sig')
        errors=message_errors(text,identity('AUTHOR'),identity('COMMITTER'))
    else:errors=check(args.base,args.head,args.event)
    for error in errors:print(error,file=sys.stderr)
    if errors:return 1
    print('Governance checks passed.')
    return 0

if __name__=='__main__':sys.exit(main())
