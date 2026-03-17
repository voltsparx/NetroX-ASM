#include "filter.h"
#include <cstring>
#include <cctype>
#include <cstdlib>

enum Field { F_STATE, F_PORT, F_PROTO, F_RTT, F_IP, F_BANNER, F_UNKNOWN };
enum Op { OP_EQ, OP_NE, OP_GT, OP_LT, OP_CONTAINS };

struct FilterTerm {
    Field field;
    Op op;
    char value[64];
    uint64_t num;
    bool is_or; // false = &&, true = ||
    FilterTerm* next;
};

struct FilterExpr {
    FilterTerm* head;
};

static void skip_ws(const char*& p) {
    while (*p && std::isspace((unsigned char)*p)) ++p;
}

static bool match_token(const char*& p, const char* tok) {
    size_t n = std::strlen(tok);
    if (std::strncmp(p, tok, n) == 0) { p += n; return true; }
    return false;
}

static Field parse_field(const char*& p) {
    if (match_token(p, "state")) return F_STATE;
    if (match_token(p, "port")) return F_PORT;
    if (match_token(p, "proto")) return F_PROTO;
    if (match_token(p, "rtt")) return F_RTT;
    if (match_token(p, "ip")) return F_IP;
    if (match_token(p, "banner")) return F_BANNER;
    return F_UNKNOWN;
}

static Op parse_op(const char*& p) {
    if (match_token(p, "!=")) return OP_NE;
    if (match_token(p, "=")) return OP_EQ;
    if (match_token(p, ">")) return OP_GT;
    if (match_token(p, "<")) return OP_LT;
    if (match_token(p, "contains")) return OP_CONTAINS;
    return OP_EQ;
}

static void parse_value(const char*& p, char* out, size_t out_sz, uint64_t& num) {
    skip_ws(p);
    num = 0;
    if (*p == '"') {
        ++p;
        size_t i = 0;
        while (*p && *p != '"' && i + 1 < out_sz) {
            out[i++] = *p++;
        }
        out[i] = 0;
        if (*p == '"') ++p;
        return;
    }
    size_t i = 0;
    const char* start = p;
    while (*p && !std::isspace((unsigned char)*p) && *p != '&' && *p != '|' ) {
        if (i + 1 < out_sz) out[i++] = *p;
        ++p;
    }
    out[i] = 0;
    // numeric parse if digits
    const char* q = start;
    bool all_digits = (*q != 0);
    while (*q && q < p) {
        if (!std::isdigit((unsigned char)*q)) { all_digits = false; break; }
        ++q;
    }
    if (all_digits) num = std::strtoull(out, nullptr, 10);
}

FilterExpr* filter_parse(const char* s) {
    if (!s || !*s) return nullptr;
    FilterExpr* expr = (FilterExpr*)std::calloc(1, sizeof(FilterExpr));
    if (!expr) return nullptr;
    FilterTerm* tail = nullptr;

    const char* p = s;
    while (*p) {
        skip_ws(p);
        if (!*p) break;
        FilterTerm* t = (FilterTerm*)std::calloc(1, sizeof(FilterTerm));
        if (!t) break;
        t->field = parse_field(p);
        skip_ws(p);
        t->op = parse_op(p);
        skip_ws(p);
        parse_value(p, t->value, sizeof(t->value), t->num);

        // operator between terms
        skip_ws(p);
        if (match_token(p, "&&")) t->is_or = false;
        else if (match_token(p, "||")) t->is_or = true;
        else t->is_or = false;

        if (!expr->head) expr->head = t;
        if (tail) tail->next = t;
        tail = t;
    }
    return expr;
}

static bool match_term(const FilterTerm* t, const PortResult* r) {
    if (!t || !r) return true;
    switch (t->field) {
    case F_STATE: {
        uint64_t v = 0;
        if (std::strcmp(t->value, "open") == 0) v = 1;
        else if (std::strcmp(t->value, "filtered") == 0) v = 2;
        else if (std::strcmp(t->value, "closed") == 0) v = 0;
        else v = t->num;
        if (t->op == OP_EQ) return r->state == v;
        if (t->op == OP_NE) return r->state != v;
        if (t->op == OP_GT) return r->state > v;
        if (t->op == OP_LT) return r->state < v;
        return false;
    }
    case F_PORT: {
        uint64_t v = t->num;
        if (t->op == OP_EQ) return r->port == v;
        if (t->op == OP_NE) return r->port != v;
        if (t->op == OP_GT) return r->port > v;
        if (t->op == OP_LT) return r->port < v;
        return false;
    }
    case F_PROTO: {
        uint64_t v = t->num;
        if (t->op == OP_EQ) return r->proto == v;
        if (t->op == OP_NE) return r->proto != v;
        return false;
    }
    case F_RTT: {
        uint64_t v = t->num;
        if (t->op == OP_EQ) return r->rtt_ns == v;
        if (t->op == OP_NE) return r->rtt_ns != v;
        if (t->op == OP_GT) return r->rtt_ns > v;
        if (t->op == OP_LT) return r->rtt_ns < v;
        return false;
    }
    case F_IP: {
        // PortResult does not carry IP in v2/v3 ABI; skip match.
        return true;
    }
    case F_BANNER: {
        if (t->op == OP_CONTAINS) return std::strstr(r->banner, t->value) != nullptr;
        if (t->op == OP_EQ) return std::strcmp(r->banner, t->value) == 0;
        if (t->op == OP_NE) return std::strcmp(r->banner, t->value) != 0;
        return false;
    }
    default:
        return true;
    }
}

bool filter_match(const FilterExpr* f, const PortResult* r) {
    if (!f || !f->head) return true;
    bool acc = match_term(f->head, r);
    const FilterTerm* t = f->head->next;
    while (t) {
        bool m = match_term(t, r);
        if (t->is_or) acc = acc || m;
        else acc = acc && m;
        t = t->next;
    }
    return acc;
}

void filter_free(FilterExpr* f) {
    if (!f) return;
    FilterTerm* t = f->head;
    while (t) {
        FilterTerm* n = t->next;
        std::free(t);
        t = n;
    }
    std::free(f);
}

