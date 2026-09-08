"""Locally edit the user's approved narration and footage; no remote generation."""
from pathlib import Path
import subprocess
import json
import hashlib

root = Path(__file__).resolve().parent
source = root.parent / 'video-01-voice-revision/Glarion-Official-YouTube.mp4'
assert hashlib.sha256(source.read_bytes()).hexdigest() == 'ad7575affbfc3f93c8058d18f227452722e626053a9c8a32fe6a997c5783876f'
items = [
    ('01-report-next-step', [(22.8, 33.0), (56.55, 61.5), (67.45, 71.4)],
     'A Security Finding Needs a Next Step | Glarion',
     'See the impact, next step and evidence in a fictional sample report. Explore it without signing up: https://glarion.app/sample-report.html?utm_source=youtube'),
    ('02-verified-monitoring', [(33.55, 49.3), (50.1, 55.65), (67.45, 71.4)],
     'From Verified Domains to Client Reports | Glarion',
     'Paid monitoring for verified domains, weekly or monthly schedules and agency-branded reports. Start with a limited free public check: https://glarion.app/?utm_source=youtube'),
]
records = []
for name, segments, title, description in items:
    filters = []
    for i, (start, end) in enumerate(segments):
        duration = end - start
        filters.extend([
            f'[0:v]trim=start={start}:end={end},setpts=PTS-STARTPTS[v{i}]',
            f'[0:a]atrim=start={start}:end={end},asetpts=PTS-STARTPTS,afade=t=in:d=0.06,afade=t=out:st={duration-0.1}:d=0.1[a{i}]',
        ])
    filters.append(''.join(f'[v{i}][a{i}]' for i in range(len(segments))) + f'concat=n={len(segments)}:v=1:a=1[v][a]')
    out = root / (name + '.mp4')
    subprocess.run(['ffmpeg', '-y', '-v', 'error', '-i', str(source), '-filter_complex', ';'.join(filters), '-map', '[v]', '-map', '[a]', '-c:v', 'libx264', '-crf', '18', '-preset', 'fast', '-c:a', 'aac', '-b:a', '192k', '-movflags', '+faststart', str(out)], check=True)
    subprocess.run(['ffmpeg', '-v', 'error', '-i', str(out), '-f', 'null', '-'], check=True)
    subprocess.run(['ffmpeg', '-y', '-v', 'error', '-ss', '1.0', '-i', str(out), '-frames:v', '1', str(root / (name + '.jpg'))], check=True)
    records.append({
        'file': out.name, 'title': title,
        'description': description + '\n\nIllustrative, fictional report data. Automated checks are not a security guarantee or a manual penetration test. Full scans require a paid plan and current proof of domain control.\nMusic: Halfway In, Anno Domini Beats, YouTube Audio Library.',
        'tags': ['Glarion', 'website security', 'digital agencies', 'client reporting', 'website monitoring'],
        'duration': sum(b - a for a, b in segments),
        'sha256': hashlib.sha256(out.read_bytes()).hexdigest(),
        'source_segments': segments,
        'format': '1920x1080 landscape, regular video (not a Short)',
        'status': 'prepared locally, not uploaded', 'decode': 'passed',
    })
(root / 'publishing-package.json').write_text(json.dumps(records, indent=2), encoding='utf8')
print(json.dumps(records, indent=2))
