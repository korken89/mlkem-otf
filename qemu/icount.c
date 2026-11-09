/*
 * QEMU TCG plugin that counts executed guest instructions. Before each `mov r12, r12` (0x46e4)
 * it writes the count so far, truncated to 32 bits, into r12, so the guest can read an exact
 * instruction counter.
 */
#include <glib.h>
#include <qemu-plugin.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static const uint16_t MARKER = 0x46e4;
static qemu_plugin_u64 count;
static struct qemu_plugin_register *r12;

static void vcpu_init(unsigned int vcpu, void *userdata)
{
    GArray *regs = qemu_plugin_get_registers();
    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *reg = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        if (strcmp(reg->name, "r12") == 0) {
            r12 = reg->handle;
        }
    }
    g_array_free(regs, TRUE);
}

static void on_marker(unsigned int vcpu, void *userdata)
{
    uint32_t n = qemu_plugin_u64_get(count, vcpu);
    guint8 bytes[4] = {n, n >> 8, n >> 16, n >> 24};
    GByteArray *buf = g_byte_array_new();
    g_byte_array_append(buf, bytes, sizeof bytes);
    qemu_plugin_write_register(r12, buf);
    g_byte_array_free(buf, TRUE);
}

static void tb_trans(struct qemu_plugin_tb *tb, void *userdata)
{
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint16_t op = 0;
        if (qemu_plugin_insn_size(insn) == 2 && qemu_plugin_insn_data(insn, &op, 2) == 2 &&
            op == MARKER) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_marker, QEMU_PLUGIN_CB_RW_REGS, NULL);
        }
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_ADD_U64, count,
                                                            1);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc,
                                           char **argv)
{
    count = qemu_plugin_scoreboard_u64(qemu_plugin_scoreboard_new(sizeof(uint64_t)));
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans, NULL);
    return 0;
}
