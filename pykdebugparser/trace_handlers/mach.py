def handle_user_svc64_exc_arm(parser, events):
    return parser.parse_event_list(events[1:-1]) if len(events) > 2 else None


handlers = {
    'User_SVC64_Exc_ARM': handle_user_svc64_exc_arm,
}
