ast_node: Ast.Node.Index,
file: Walk.File.Index,
/// The decl whose namespace this is in.
parent: Index,

pub const ExtraInfo = struct {
    is_pub: bool,
    name: []const u8,
    /// This might not be a doc_comment token in which case there are no doc comments.
    first_doc_comment: Ast.TokenIndex,
};

pub const Index = enum(u32) {
    none = std.math.maxInt(u32),
    _,

    pub fn get(i: Index) *Decl {
        return &Walk.decls.items[@intFromEnum(i)];
    }
};

pub fn is_pub(d: *const Decl) bool {
    return d.extra_info().is_pub;
}

pub fn extra_info(d: *const Decl) ExtraInfo {
    const ast = d.file.get_ast();
    const token_tags = ast.tokens.items(.tag);
    const node_tags = ast.nodes.items(.tag);
    switch (node_tags[d.ast_node]) {
        .root => return .{
            .name = "",
            .is_pub = true,
            .first_doc_comment = if (token_tags[0] == .container_doc_comment)
                0
            else
                token_tags.len - 1,
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = ast.fullVarDecl(d.ast_node).?;
            const name_token = var_decl.ast.mut_token + 1;
            assert(token_tags[name_token] == .identifier);
            const ident_name = ast.tokenSlice(name_token);
            return .{
                .name = ident_name,
                .is_pub = var_decl.visib_token != null,
                .first_doc_comment = findFirstDocComment(ast, var_decl.firstToken()),
            };
        },

        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto = ast.fullFnProto(&buf, d.ast_node).?;
            const name_token = fn_proto.name_token.?;
            assert(token_tags[name_token] == .identifier);
            const ident_name = ast.tokenSlice(name_token);
            return .{
                .name = ident_name,
                .is_pub = fn_proto.visib_token != null,
                .first_doc_comment = findFirstDocComment(ast, fn_proto.firstToken()),
            };
        },

        else => |t| {
            log.debug("hit '{s}'", .{@tagName(t)});
            unreachable;
        },
    }
}

pub fn value_node(d: *const Decl) ?Ast.Node.Index {
    const ast = d.file.get_ast();
    const node_tags = ast.nodes.items(.tag);
    const token_tags = ast.tokens.items(.tag);
    return switch (node_tags[d.ast_node]) {
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        .root,
        => d.ast_node,

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = ast.fullVarDecl(d.ast_node).?;
            if (token_tags[var_decl.ast.mut_token] == .keyword_const)
                return var_decl.ast.init_node;

            return null;
        },

        else => null,
    };
}

pub fn categorize(decl: *const Decl) Walk.Category {
    return decl.file.categorize_decl(decl.ast_node);
}

/// Looks up a direct child of `decl` by name.
pub fn get_child(decl: *const Decl, name: []const u8) ?Decl.Index {
    switch (decl.categorize()) {
        .alias => |aliasee| return aliasee.get().get_child(name),
        .namespace => |node| {
            const file = decl.file.get();
            const scope = file.scopes.get(node) orelse return null;
            const child_node = scope.get_child(name) orelse return null;
            return file.node_decls.get(child_node);
        },
        else => return null,
    }
}

/// Looks up a decl by name accessible in `decl`'s namespace.
pub fn lookup(decl: *const Decl, name: []const u8) ?Decl.Index {
    const namespace_node = switch (decl.categorize()) {
        .namespace => |node| node,
        else => decl.parent.get().ast_node,
    };
    const file = decl.file.get();
    const scope = file.scopes.get(namespace_node) orelse return null;
    const resolved_node = scope.lookup(&file.ast, name) orelse return null;
    return file.node_decls.get(resolved_node);
}

/// Appends the fully qualified name to `out`, using `sep` as the component
/// delimiter.
pub fn fqn(decl: *const Decl, out: *std.ArrayListUnmanaged(u8), sep: u8, encode: bool) Oom!void {
    try decl.append_path(out, sep, encode);
    if (decl.parent != .none) {
        try append_parent_ns(out, decl.parent, sep, encode);
        try append_maybe_encoded(out, decl.extra_info().name, encode);
    } else {
        out.items.len -= 1; // remove the trailing separator
    }
}

pub fn reset_with_path(decl: *const Decl, list: *std.ArrayListUnmanaged(u8), sep: u8, encode: bool) Oom!void {
    list.clearRetainingCapacity();
    try append_path(decl, list, sep, encode);
}

pub fn append_path(decl: *const Decl, list: *std.ArrayListUnmanaged(u8), sep: u8, encode: bool) Oom!void {
    // Prefer the module name alias.
    for (Walk.modules.keys(), Walk.modules.values()) |pkg_name, pkg_file| {
        if (pkg_file == decl.file) {
            try append_maybe_encoded(list, pkg_name, encode);
            try list.append(gpa, sep);
            return;
        }
    }

    const file_path = decl.file.path();
    var file_path_components = std.mem.splitScalar(u8, file_path, '/');
    try append_maybe_encoded(list, file_path_components.first(), encode);
    while (file_path_components.next()) |component| {
        try list.append(gpa, sep);
        try append_maybe_encoded(list, component, encode);
    }
    if (encode and std.mem.endsWith(u8, list.items, "%2Ezig")) {
        list.items.len -= "%2Ezig".len;
    } else if (!encode and std.mem.endsWith(u8, list.items, ".zig")) {
        list.items.len -= ".zig".len;
    }
    try list.append(gpa, sep);
}

pub fn append_parent_ns(list: *std.ArrayListUnmanaged(u8), parent: Decl.Index, sep: u8, encode: bool) Oom!void {
    assert(parent != .none);
    const decl = parent.get();
    if (decl.parent != .none) {
        try append_parent_ns(list, decl.parent, sep, encode);
        try append_maybe_encoded(list, decl.extra_info().name, encode);
        try list.append(gpa, sep);
    }
}

fn append_maybe_encoded(list: *std.ArrayListUnmanaged(u8), s: []const u8, encode: bool) Oom!void {
    if (encode) {
        try append_encoded(list, s);
    } else {
        try list.appendSlice(gpa, s);
    }
}

pub fn append_encoded(list: *std.ArrayListUnmanaged(u8), s: []const u8) Oom!void {
    try std.Uri.Component.percentEncode(list.writer(gpa), s, struct {
        fn is_valid(c: u8) bool {
            // Certain characters are used by Autodoc for special purposes and
            // must be encoded to avoid ambiguity.
            return switch (c) {
                '.', // path delimiter
                '?', // search query delimiter
                => false,
                else => std.Uri.isFragmentChar(c),
            };
        }
    }.is_valid);
}

pub fn findFirstDocComment(ast: *const Ast, token: Ast.TokenIndex) Ast.TokenIndex {
    const token_tags = ast.tokens.items(.tag);
    var it = token;
    while (it > 0) {
        it -= 1;
        if (token_tags[it] != .doc_comment) {
            return it + 1;
        }
    }
    return it;
}

/// Successively looks up each component.
pub fn find(search_string: []const u8, delim: u8) Decl.Index {
    var path_components = std.mem.splitScalar(u8, search_string, delim);
    const file = Walk.modules.get(path_components.first()) orelse return .none;
    var current_decl_index = file.findRootDecl();
    while (path_components.next()) |component| {
        while (true) switch (current_decl_index.get().categorize()) {
            .alias => |aliasee| current_decl_index = aliasee,
            else => break,
        };
        current_decl_index = current_decl_index.get().get_child(component) orelse return .none;
    }
    return current_decl_index;
}

const Decl = @This();
const std = @import("std");
const Ast = std.zig.Ast;
const Walk = @import("Walk.zig");
const gpa = std.heap.wasm_allocator;
const assert = std.debug.assert;
const log = std.log;
const Oom = error{OutOfMemory};
