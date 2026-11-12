# 统一 PR 合并门禁

最终提交状态名为 **`PR Merge Gate`**。它由 main 上的可信策略发布到 PR 当前
head SHA。实现入口、独立只读审查、限次回修及用户决定 squash 合并的流程保持不变。
本门禁不合并 PR、不发版、不操作服务器。

## 判定

`scripts/ci/pr_merge_gate_policy.json` 是必需 workflow、矩阵 job、步骤的明确清单：

- CI：两版 Ubuntu、Debian/Rocky/Alma 单元集成与 release、真实 Chain 流量、菜单、外部客户端及迁移。
- schema（包括复用的 source matrix 和 default Release 验收）、v0.2.1 读取兼容。
- VLESS/Sudoku 互通与产物/日志审计、Chain 双平台 systemd、旧版实例升级。
- Ubuntu/Debian 完整生命周期及回滚、双平台性能可靠性、RustSec。
- 门禁自身回归与独立 Codex Review。

每个必需 suite 只接受本仓库 Actions API 中 **当前 head 的 pull_request 运行**，
同时绑定 PR 编号及 base SHA，以最新 run ID 为准，并合并截至最新 attempt 的各 job 最新执行，
保留仅重跑失败 job 时此前成功的证据；不使用同名 status、
其他 PR、push、手动运行或旧 SHA 的绿灯。
workflow、每个 job、清单中的每个步骤必须 completed/success；缺失、失败、取消、超时、
neutral、skipped 均阻止。写回前再次读取运行 attempt 和 PR head/base，API 错误也阻止。
清单以外新出现的 job 也必须成功。

独立审查的 bot 评论须有唯一的 `codex-review-verdict` 标记，绑定 head、base、
发现数、真实 run ID/attempt，并从该 run 下载可信 publication 步骤生成的机器证明产物
交叉核对，其他 bot 评论即使重放旧 Review run 的标记也不能冒充当前审查。
只接受发现数为 0、可信 Review workflow 实际成功且
只读隔离、模型执行、读取/完成验证和发布步骤均成功的证明。关闭 Review、草稿尚未
实际审查、非所有者 PR 不符合现有审查准入等情况均保持阻止，不伪造审查成功。
旧版仅有 status=complete 的评论不足以通过，部署后需要重新运行审查。
证明产物保留 90 天，过期或删除时需要重新审查，不降级为仅信任评论。
Review 使用确定性 run-name，在排队阶段即将 PR CI 触发的自动运行绑定 head、手动运行绑定 PR。
push CI 触发的非审查运行使用空目标，不参与必需 Review 判定，保留原有跳过规则。
门禁从 Actions 元数据中选最新运行，尚未发布任何评论的失败、取消或跳过也会阻止，
每个新 Review run/attempt 均必须实际执行审查、发布并上传自己的可信证明。
同 head/base 的旧成功评论和证明不能替代新运行；即使 CI 重跑再次触发 Review，
其中必需步骤被跳过、失败或取消时依然阻止合并。仅同 run/attempt 的完全相同评论
允许幂等处理，且不可跳过本次审查或证明上传。
写回前再次检查证明运行的 attempt 及是否已有更新的 Review。

专用套件的 PR 路径过滤移除，性能套件增加 PR 事件，保证文档或 workflow 改动也有
当前 head 的完整证据。push 和定时测试范围、命令、断言与既有权限不变。
常规 cargo 套件的 ignored/helper demo 不充当实际 E2E 证据，使用专用流量/systemd
步骤证明必需 E2E。现有按平台不适用的步骤（Ubuntu 22 的 install-self、非指定平台的
direct fallback）和失败诊断不列为必需；相应验收在 Ubuntu 24 / Debian 的必需步骤执行。
维护者新增或改名必需测试时应同步清单，不能靠清单删项规避失败。

## 触发及安全边界

PR 事件、必需 workflow 的 completed、每 15 分钟兜底检查以及 main 上手动触发会重新计算。
workflow_run 事件只处理关联的当前 PR，忽略 push 和旧 head，避免每个事件全仓扫描。
requested/in_progress 只对关联 PR 轻量发布 pending，重新运行开始后撤销旧绿灯；新提交因 SHA 不同天然没有
旧状态可用。GitHub 事件和定时调度可能延迟，运行重试期间应等待新一轮门禁完成。
发布过程串行，不取消中途运行；门禁读取失败后应排查日志并手动重跑，不无限重试测试。

带 statuses:write 的发布 job 只 checkout main 的策略，不运行 PR 源码、脚本或产物，
不读取 secrets，不授予 contents:write、actions:write 或合并权限。外部输入仅从环境
变量和事件文件读取，API 请求有超时及分页上限。PR 中的回归 job 仅 contents:read。
门禁 workflow 自身成功仅表示完成判定，最终结果见 PR head 的 `PR Merge Gate` status
及运行 Summary；判定不满足会发布 failure。

## Rulesets 配置与首次上线

1. 此 PR 经用户批准合入 main 后，确认 main 上已经有门禁脚本与工作流。
   本 PR 中的门禁实现和回归可以在 Actions 测试，但默认分支事件发布路径在合入前
   尚未生效，不能把候选回归当作可信发布路径已上线。
2. 为目标 `main` 创建/编辑 Active 分支 Ruleset，开启 Require a pull request before
   merging 和 Require status checks to pass。增加精确名称 **`PR Merge Gate`**，
   来源选择 **GitHub Actions**；推荐开启 Require branches to be up to date before merging。
3. 若名称尚未出现，对一个打开的 PR 在 main 上手动运行 `PR Merge Gate`（pr 参数），
   等待状态创建后再选择。保留已有 required checks、安全限制和审核规则，勿新增 bypass。
4. 配置后在打开的 PR 上核实该 status 绑定当前 head；新提交后等待完整测试与独立审查。
   有问题时看 status 链接中的 Summary，修复同一 PR，再等新 SHA 的完整证据。

不自动修改仓库 Rulesets。状态来源为 GitHub Actions 应用，GitHub 的来源绑定不能区分
同一应用下的不同 workflow；应保留对工作流和策略文件的人工审查及既有仓库写权限限制。
本方案针对现有 PR 模式，未启用 merge queue/merge_group；启用队列前须另行增加合成提交验证。
