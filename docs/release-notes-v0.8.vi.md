# byreis v0.8 release notes

v0.8 ship `byreis run`, verb process-injection admin-only. Nó decrypt
file-of-record live của một project và chạy một command với mọi value
được inject vào environment của command đó — secrets được hand cho
một single child process và không bao giờ rời process byreis qua channel
nào khác. Đây là pattern consume security-aligned share với `op run` và
`doppler run`: follow-on cho v0.7 `export`, release của nó explicit
record injection kiểu `op run` là candidate v0.8 sanctioned.

Asymmetric-access guarantee không thay đổi. `byreis run -- <cmd>` là
một command admin-only — nó decrypt bằng admin private key, nên một
contributor keyless bị deny ở permission matrix trước bất kỳ decrypt
hay child spawn nào. Contributor access vẫn write-only và enforce
cryptographically; không có v0.8 surface nào thay đổi permission
matrix contributor. Không có crypto mới và không có thay đổi
secrets-format: `run` đi qua đường decrypt admin-read đã ship.

## Có gì mới

### `byreis run` — process injection admin-only

`byreis run` decrypt file-of-record live của một project và chạy
command sau `--` với mọi value được inject vào environment của nó.

```
byreis run --project <id> --file <name> -- ./deploy.sh
byreis run --project <id> --file <name> -- printenv DATABASE_URL
```

#### Gate admin-only

`byreis run -- <cmd>` là một command admin-only; nó decrypt bằng
admin private key, nên một contributor keyless bị deny ở permission
matrix trước bất kỳ decrypt hay child spawn nào. Deny xảy ra trước
bất kỳ network contact, identity load, hay decrypt attempt nào —
cùng ordering fail-closed mà `get`, `decrypt`, và `export` follow.
Whole file được decrypt fail-closed: nếu bất kỳ value nào không
decrypt được, không child nào được spawn.

Audit trail record một event `op=run` để một injection run
distinguishable khỏi một `decrypt` single-key hay một bulk `export`
trong admin audit log. Chỉ operation literal được record — không
bao giờ argument của child command hay bất kỳ secret value nào.

#### Inject vào environment-only, không bao giờ argv

byreis inject mọi value đã decrypt vào environment của child process
only — không bao giờ vào argv. Argv của một process là
world-readable qua `ps`, nên một secret đặt ở đó sẽ leak ra mọi
user trên host. Secrets không bao giờ chạm disk qua byreis và chỉ
tồn tại trong vòng đời của child.

#### `exec`, không phải shell

byreis exec command sau `--` trực tiếp — nó KHÔNG interpret `$VAR`,
chạy shell, hay expand glob, pipe, hay redirect. Argument vector
bạn viết sau `--` chính xác là argument vector child nhận. Nếu bạn
muốn behavior shell, chạy `byreis run -- sh -c '...'` (mà sau đó
bạn owns). Exec argv trực tiếp nghĩa là một secret value không bao
giờ bị byreis reinterpret thành shell command — surface
shell-injection bị eliminate ở boundary.

#### Behavior environment-override

Một biến do byreis inject override một biến parent-environment
inherited cùng tên — injected-wins. Nếu parent environment đã define
một biến mà file secrets cũng define, child thấy value đã decrypt
từ file, không phải value inherited. (Một collision giữa hai
byreis-internal key map sang cùng environment variable name vẫn là
một hard error: không child nào được spawn.)

#### Inherited stdio, không pty

byreis inherit stdin, stdout, và stderr của child trực tiếp — nó
không allocate pty và không bao giờ capture hay filter output của
child. Child thấy real terminal. Exit code của child, bao gồm
signal termination report là `128 + signal`, được pass thẳng qua
như exit code của byreis.

#### Disclosure thẳng thắn về residual-exposure

byreis chỉ hứa rằng bản thân byreis không leak gì và secrets không
bao giờ chạm disk qua byreis — cùng mô hình với `op run` và
`doppler run`. Khi child đã giữ environment, lời hứa đó kết thúc.
byreis KHÔNG protect được những cái sau:

- Child và mọi descendant của nó inherit environment, làm một secret
  inject readable qua `/proc/<pid>/environ` bởi các process
  cùng-uid trong suốt vòng đời child hoặc descendant còn sống.
- Một sub-child đặt một secret inherited vào CHÍNH argv của nó
  re-expose value đó qua `ps`. byreis chỉ control được argv của
  direct child mình spawn, không control được những gì descendant
  làm với environment inherited.
- Một core dump của child hoặc crash reporter có thể capture
  environment, bao gồm secrets đã inject.
- Nếu process byreis tự nó bị force-kill (SIGKILL), child mà nó
  spawn được reparent (về init) và giữ secrets đã inject trong
  environment cho đến khi nó exit — byreis không forward được một
  signal nó không bao giờ nhận.

Nếu bất kỳ cái nào trong số đó nằm trong threat model của bạn,
restrict secret xuống child hẹp nhất có thể, disable core dump cho
process đó, và đối xử với environment đã inject như plaintext bạn
giờ owns.

## Cái KHÔNG có trong v0.8

Các cái sau được carry forward sang một release tương lai và không
available trong v0.8:

- **Không có filter `--key`.** `run` luôn decrypt và inject whole
  file. Injection subset per-key không support trong release này.
- **Không có shell interpretation.** byreis exec post-`--` argv
  trực tiếp và sẽ không bao giờ interpret `$VAR`, chạy shell, hay
  expand glob/pipe/redirect dùm bạn. Dùng `byreis run -- sh -c '...'`
  nếu bạn cần một shell.
- **Không có flag `--strict-env`.** Default v0.8 là injected-wins
  (một biến injected override một inherited cùng tên); không có
  mode opt-in biến một collision inherited/injected thành một error.
- **Không có support GitLab.** byreis là GitHub-only trong v0.8.
  GitLab support không plan cho release này.

## Upgrade

Drop-in replacement cho v0.7. Không có thay đổi secrets-format,
không có thay đổi registry-schema, không có thay đổi environment
variable. Các file encrypted, registry, signed commit hiện có, và
contract hai-biến `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO` đều
không bị ảnh hưởng. Verb `run` là additive; mọi command hiện có
tiếp tục hoạt động identical.
