ALTER TABLE `short_link` DROP FOREIGN KEY `short_link_user_id_users_id_fk`;
--> statement-breakpoint
ALTER TABLE `short_link` ADD CONSTRAINT `short_link_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;